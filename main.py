import asyncio
import aiohttp
import time
import re
import base64
import os
import subprocess
import tarfile
import requests

# 配置文件
SOURCES_FILE = 'sources.txt'
OUTPUT_FILE = 'valid_nodes.txt'
SUBCONVERTER_URL = "https://github.com/tindy2013/subconverter/releases/download/v0.9.0/subconverter_linux64.tar.gz"
# 并发数，GitHub Action 性能强，可以拉高
CONCURRENCY = 200 
# 超时时间 (秒)，超过这个时间没连上算死节点
TIMEOUT = 3 

# 测速目标：使用 Cloudflare 或 Google 的端口进行 TCP 握手
TEST_HOST = "www.google.com"
TEST_PORT = 80

def install_subconverter():
    if os.path.exists("subconverter/subconverter"):
        return
    print("[*] Downloading Subconverter engine...")
    r = requests.get(SUBCONVERTER_URL, stream=True)
    with open("subconverter.tar.gz", "wb") as f:
        for chunk in r.iter_content(chunk_size=1024):
            f.write(chunk)
    
    print("[*] Extracting...")
    with tarfile.open("subconverter.tar.gz", "r:gz") as tar:
        tar.extractall()
    print("[+] Subconverter installed.")

def normalize_nodes():
    """利用本地 subconverter 将乱七八糟的源统一转为 vmess/ss/trojan 链接"""
    with open(SOURCES_FILE, 'r') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not sources:
        print("[-] No sources found.")
        return []

    # 构造 subconverter 的参数，将所有源通过管道符合并
    raw_urls = "|".join(sources)
    # 只要节点部分，不要分组信息
    target_url = f"http://127.0.0.1:25500/sub?target=mixed&url={requests.utils.quote(raw_urls)}"
    
    # 启动后台进程
    proc = subprocess.Popen(["./subconverter/subconverter"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3) # 等待启动
    
    try:
        print("[*] Normalizing & merging subscriptions via Subconverter...")
        resp = requests.get(target_url, timeout=30)
        if resp.status_code == 200:
            content = resp.text
            # 有些时候返回的是 Base64，需要解码
            try:
                if 'vmess://' not in content and 'ss://' not in content:
                    content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except:
                pass
            
            nodes = content.splitlines()
            print(f"[+] Retrieved {len(nodes)} raw nodes after normalization.")
            return nodes
    except Exception as e:
        print(f"[-] Subconverter failed: {e}")
    finally:
        proc.kill()
    return []

async def tcp_ping(session, node_line):
    """
    解析节点并尝试 TCP 握手。
    这里为了极其简单，我们只从节点字符串里提取 Address 和 Port (如果是明文)
    或者仅仅做一个简单的存活检查。
    由于 vmess/ss 格式复杂，我们采用一种取巧的办法：
    真正的测速需要完整解析，但在 Action 里，我们假设：
    如果在 'mixed' 模式下，subconverter 返回的通常是解释过的。
    
    **极限模式**：我们只通过 Python 解析 URL 里的地址和端口进行连接测试。
    """
    # 简单的正则提取 IP/Domain 和 Port
    # 适配 ss://, vmess://(json), trojan://, vless://
    # 这部分极其复杂，为了代码短小精悍，我们直接判定：
    # 如果 Action 里跑完整测速内核太重，我们只做“清洗”和“去重”，
    # 如果你一定要测速，必须解析出 server 和 port。
    
    # 这里我们使用一个假设：如果节点能被解析，我们就认为它是候选。
    # 真正的 connectivity check 需要解析 vmess json 或 ss base64。
    # 下面是一个极简的 vmess/ss/trojan 解析器。
    
    try:
        host = None
        port = None
        
        # 预处理
        link = node_line.strip()
        if not link: return None
        
        if link.startswith('vmess://'):
            # vmess base64 json
            b64 = link[8:]
            pad = len(b64) % 4
            if pad: b64 += '=' * (4 - pad)
            info = requests.utils.json.loads(base64.b64decode(b64).decode('utf-8'))
            host = info.get('add')
            port = info.get('port')
            
        elif link.startswith('ss://'):
            # ss logic (simplified)
            # ss://base64#name or ss://method:pass@host:port
            try:
                main = link.split('ss://')[1].split('#')[0]
                if '@' in main:
                    host_port = main.split('@')[1]
                    host, port = host_port.split(':')
                else:
                    # decode base64
                    pad = len(main) % 4
                    if pad: main += '=' * (4 - pad)
                    decoded = base64.b64decode(main).decode('utf-8')
                    # method:pass@host:port
                    host, port = decoded.split('@')[1].split(':')
            except:
                pass

        elif link.startswith('trojan://') or link.startswith('vless://'):
             # trojan://pass@host:port
             try:
                main = link.split('://')[1].split('#')[0]
                host_port = main.split('@')[1]
                # handle params ?...
                host_port = host_port.split('?')[0]
                host, port = host_port.split(':')
             except:
                pass

        if host and port:
            start = time.time()
            try:
                # 真正的 TCP 握手
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, int(port)), 
                    timeout=TIMEOUT
                )
                latency = (time.time() - start) * 1000
                writer.close()
                await writer.wait_closed()
                return (latency, node_line)
            except:
                return None
        else:
            # 无法解析地址的，保留但标记为未测试，或者直接丢弃 (极端模式：丢弃)
            return None 

    except Exception:
        return None

async def check_all_nodes(nodes):
    print(f"[*] Starting TCP connectivity check for {len(nodes)} nodes...")
    tasks = []
    conn = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=conn) as session:
        for node in nodes:
            tasks.append(tcp_ping(session, node))
        
        results = await asyncio.gather(*tasks)
    
    # 过滤掉 None，按延迟排序
    valid = [r for r in results if r is not None]
    valid.sort(key=lambda x: x[0]) # 延迟低的在前
    return valid

def main():
    install_subconverter()
    
    # 1. 统一格式清洗
    raw_nodes = normalize_nodes()
    if not raw_nodes:
        return

    # 2. 只有 vmess/ss/trojan/vless 才会被放入测速队列
    # 过滤掉杂质
    targets = [n for n in raw_nodes if n.startswith(('vmess://', 'ss://', 'trojan://', 'vless://'))]
    
    # 3. 异步测速
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(check_all_nodes(targets))
    
    print(f"[*] Alive nodes: {len(results)} / {len(targets)}")
    
    if results:
        # 4. 打包输出
        final_lines = [r[1] for r in results]
        final_str = "\n".join(final_lines)
        b64_output = base64.b64encode(final_str.encode('utf-8')).decode('utf-8')
        
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_output)
        print(f"[+] Successfully saved to {OUTPUT_FILE} (Base64 encoded).")
    else:
        print("[-] All nodes died.")

if __name__ == "__main__":
    main()
