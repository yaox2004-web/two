import base64
import re
import socket
from concurrent.futures import ThreadPoolExecutor
import requests

# 1. 节点抓取源 (可自行补充/替换)
SOURCES = [
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://www.ermao.net/sub/v2ray/ermao.net"
]

TIMEOUT = 2.0        # TCP 建连超时时间 (秒)
MAX_WORKERS = 30     # 并发并发测速线程数

def fetch_raw_nodes() -> list[str]:
    """抓取源数据并解码出原始节点列表"""
    nodes = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for url in SOURCES:
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                content = resp.text.strip()
                # 尝试 Base64 解码
                try:
                    # 补齐 base64 填充符
                    missing_padding = len(content) % 4
                    if missing_padding:
                        content += '=' * (4 - missing_padding)
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    nodes.extend(decoded.splitlines())
                except Exception:
                    nodes.extend(content.splitlines())
        except Exception as e:
            print(f"抓取源失败 {url}: {e}")
    return list(set(filter(None, nodes)))

def parse_node_target(node_str: str) -> tuple[str, int] | None:
    """提取节点的 IP/域名 和 端口用于 TCP 测试"""
    try:
        if node_str.startswith("vmess://"):
            import json
            b64_body = node_str.replace("vmess://", "")
            missing_padding = len(b64_body) % 4
            if missing_padding:
                b64_body += '=' * (4 - missing_padding)
            info = json.loads(base64.b64decode(b64_body).decode('utf-8', errors='ignore'))
            return info.get("add"), int(info.get("port", 443))
        elif any(node_str.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
            # 解析 URL 格式中的 host:port
            match = re.search(r'@([^:/]+):(\d+)', node_str)
            if match:
                return match.group(1), int(match.group(2))
    except Exception:
        pass
    return None

def tcp_check(node_str: str) -> str | None:
    """TCP 端口测速联通性检验"""
    target = parse_node_target(node_str)
    if not target or not target[0]:
        return None
    
    host, port = target
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return node_str
    except Exception:
        pass
    return None

def main():
    print("开始获取节点列表...")
    raw_nodes = fetch_raw_nodes()
    print(f"共抓取到 {len(raw_nodes)} 个节点，开始 TCP 连通性测试...")

    valid_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(tcp_check, raw_nodes)
        for res in results:
            if res:
                valid_nodes.append(res)

    print(f"测试完成！有效节点数量: {len(valid_nodes)}")

    # 导出为标准 Base64 订阅文件
    output_content = "\n".join(valid_nodes)
    encoded_sub = base64.b64encode(output_content.encode('utf-8')).decode('utf-8')
    
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_sub)
    print("已成功更新 sub.txt 文件")

if __name__ == "__main__":
    main()
