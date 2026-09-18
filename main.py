import base64
import json
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------- 配置 ----------------

SOURCES = [
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://www.ermao.net/sub/v2ray/ermao.net",
    "https://raw.githubusercontent.com/m24231/free-v2ray-nodes/master/v2ray.txt",
    "https://raw.githubusercontent.com/Pawroid/Free-Servers/main/sub",
    "https://raw.githubusercontent.com/EternityPioneer/V2rayFreeSub/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreFreeFron/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/NodeFree/NodeFree/main/sub",
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")

TCP_TIMEOUT = 2.0
TCP_WORKERS = 64

REAL_TIMEOUT = 5.0        # 单个 URL 探测超时（秒）
REAL_WORKERS = 16         # 并发运行的 xray 进程数
REAL_MAX_NODES = 400      # 最多对前 N 个 TCP 存活节点做真实测试

# 多 URL 交叉验证
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
MIN_PROBE_PASS = 2        # 至少几个 URL 通过才算这个节点可用

XRAY_BIN = "./xray"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

CACHE_FILE = "node_cache.json"

# ---------------- 工具函数 ----------------

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    retry = Retry(
        total=3, backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16))
    s.mount("http://", HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16))
    return s


def b64_decode_loose(s: str) -> str | None:
    if not s:
        return None
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception:
        return None


def is_subscription(text: str) -> bool:
    if not text:
        return False
    for line in text.splitlines():
        line = line.strip()
        if line and any(line.startswith(s) for s in SCHEMES):
            return True
    return False


def node_name(node: str) -> str:
    """从节点链接里取一个友好名字"""
    if "#" in node:
        name = node.split("#", 1)[1].split("?", 1)[0]
        try:
            name = unquote(name)
        except Exception:
            pass
        if name.strip():
            return name.strip()
    target = parse_node_target(node)
    if target:
        return f"{target[0]}:{target[1]}"
    return "node"


# ---------------- 1. 并发抓源 ----------------

def fetch_one(session, url):
    try:
        r = session.get(url, timeout=10)
        r.raise_for_status()
        return url, r.text.strip(), None
    except Exception as e:
        return url, None, str(e)


def fetch_raw_nodes(session) -> set[str]:
    nodes: set[str] = set()
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
        futs = {ex.submit(fetch_one, session, u): u for u in SOURCES}
        for fut in as_completed(futs):
            url, text, err = fut.result()
            if err:
                print(f"[抓取失败] {url}: {err}")
                continue
            decoded = b64_decode_loose(text)
            if decoded and is_subscription(decoded):
                text = decoded
            for line in text.splitlines():
                line = line.strip()
                if line and any(line.startswith(s) for s in SCHEMES):
                    nodes.add(line)
    return nodes


# ---------------- 2. TCP 预筛 ----------------

def parse_node_target(node: str):
    try:
        if node.startswith("vmess://"):
            info = json.loads(b64_decode_loose(node[8:]) or "")
            host = str(info.get("add", "")).strip().strip("[]")
            port = int(info.get("port", 443))
            return (host, port) if host and 0 < port < 65536 else None

        if node.startswith("ssr://"):
            decoded = b64_decode_loose(node[6:])
            if decoded:
                parts = decoded.split(":")
                if len(parts) >= 2:
                    return parts[0].strip("[]"), int(parts[1])

        parsed = urlparse(node)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port

        if node.startswith("ss://"):
            body = node[5:].split("#", 1)[0].split("?", 1)[0]
            decoded = b64_decode_loose(body)
            if decoded:
                m = re.search(r"@(.+):(\d+)$", decoded)
                if m:
                    return m.group(1).strip("[]"), int(m.group(2))
    except Exception:
        pass
    return None


def tcp_check(node: str):
    target = parse_node_target(node)
    if not target:
        return None
    host, port = target
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return node, (time.perf_counter() - t0) * 1000
    except Exception:
        return None


# ---------------- 3. 缓存评分 ----------------

def load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: dict):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def node_score(node: str, cache: dict) -> float:
    """越大越优先真实测试；未知节点给中等分"""
    info = cache.get(node)
    if not info:
        return 0.5
    s = info.get("success", 0)
    f = info.get("fail", 0)
    total = s + f
    if total == 0:
        return 0.5

    rate = s / total
    recency = 0.3 if (info.get("last_success", 0)
                      and time.time() - info["last_success"] < 86400) else 0.0
    lat = info.get("last_latency", 9999)
    lat_score = max(0.0, 1 - lat / 2000) * 0.2
    return rate * 0.5 + recency + lat_score


# ---------------- 4. Xray 内核 ----------------

def ensure_xray(path: str = XRAY_BIN) -> str:
    if os.path.exists(path) and os.access(path, os.X_OK):
        return path
    print("未检测到 xray，正在下载...")
    r = requests.get(XRAY_URL, stream=True, timeout=60)
    r.raise_for_status()
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)
        zip_path = f.name
    try:
        with zipfile.ZipFile(zip_path) as z:
            for name in z.namelist():
                if name == "xray":
                    with z.open(name) as src, open(path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.chmod(path, 0o755)
                    break
    finally:
        os.unlink(zip_path)
    print("xray 已就绪")
    return path


# ---------------- 5. 节点 -> Xray outbound ----------------

def _stream_settings(net, security, tls_opts, q):
    stream = {"network": net, "security": security}
    if security == "tls":
        stream["tlsSettings"] = tls_opts
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }
    if net == "ws":
        ws = {"path": q.get("path", "/")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName") or q.get("path", "")}
    elif net in ("h2", "http"):
        h2 = {"path": q.get("path", "/")}
        if q.get("host"):
            h2["host"] = [q["host"]]
        stream["httpSettings"] = h2
    elif net == "tcp" and q.get("headerType") == "http":
        stream["tcpSettings"] = {"header": {"type": "http",
                                            "request": {"path": [q.get("path", "/")]}}}
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": q.get("path", "/")}
    return stream


def vmess_to_outbound(info: dict):
    host = str(info.get("add", "")).strip()
    if not host or not info.get("id"):
        return None
    port = int(info.get("port", 443))
    net = info.get("net", "tcp")
    tls_on = (info.get("tls", "") or "").lower() in ("tls", "reality")
    sni = info.get("sni") or info.get("host") or host
    q = {"path": info.get("path", "/"), "host": info.get("host", ""),
         "serviceName": info.get("path", ""), "headerType": info.get("type", "")}
    if (info.get("tls", "") or "").lower() == "reality":
        q.update({"sni": sni, "fp": info.get("fp", "chrome"),
                  "pbk": info.get("pbk", ""), "sid": info.get("sid", ""),
                  "spx": info.get("spx", "")})
        stream = _stream_settings(net, "reality", None, q)
    else:
        stream = _stream_settings(net, "tls" if tls_on else "none",
                                  {"serverName": sni, "allowInsecure": False}, q)
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
                                "users": [{"id": info["id"],
                                           "alterId": int(info.get("aid", 0)),
                                           "security": info.get("scy", "auto")}]}]},
        "streamSettings": stream,
    }


def vless_to_outbound(node: str):
    u = urlparse(node)
    if not u.hostname or not u.username:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    net, sec = q.get("type", "tcp"), q.get("security", "none")
    tls_opts = {"serverName": q.get("sni") or u.hostname,
                "allowInsecure": q.get("allowInsecure", "0") == "1"}
    stream = _stream_settings(net, sec, tls_opts, q)
    user = {"id": u.username, "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]
    return {"protocol": "vless",
            "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443,
                                    "users": [user]}]},
            "streamSettings": stream}


def trojan_to_outbound(node: str):
    u = urlparse(node)
    if not u.hostname or not u.username:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    tls_opts = {"serverName": q.get("sni") or u.hostname,
                "allowInsecure": q.get("allowInsecure", "0") == "1"}
    stream = _stream_settings(q.get("type", "tcp"), "tls", tls_opts, q)
    return {"protocol": "trojan",
            "settings": {"servers": [{"address": u.hostname, "port": u.port or 443,
                                      "password": u.username}]},
            "streamSettings": stream}


def parse_ss(node: str):
    """ss:// -> (method, password, host, port)"""
    body = node[5:].split("#", 1)[0]
    if "?" in body:
        body = body.split("?", 1)[0]
    if "@" not in body:
        decoded = b64_decode_loose(body)
        if not decoded:
            return None
        m = re.match(r"(.+?):(.+)@(.+):(\d+)$", decoded)
        if not m:
            return None
        return m.group(1), m.group(2), m.group(3), int(m.group(4))

    userinfo, hostport = body.rsplit("@", 1)
    decoded = b64_decode_loose(userinfo)
    if decoded and ":" in decoded:
        method, password = decoded.split(":", 1)
    elif ":" in userinfo:
        method, password = userinfo.split(":", 1)
    else:
        return None

    if hostport.startswith("["):
        host, port_s = hostport[1:].split("]:", 1)
    else:
        host, port_s = hostport.rsplit(":", 1)
    return method, password, host, int(port_s)


def ss_to_outbound(node: str):
    parsed = parse_ss(node)
    if not parsed:
        return None
    method, password, host, port = parsed
    return {"protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                                      "method": method, "password": password}]},
            "streamSettings": {"network": "tcp"}}


def node_to_outbound(node: str):
    try:
        if node.startswith("vmess://"):
            return vmess_to_outbound(json.loads(b64_decode_loose(node[8:]) or ""))
        if node.startswith("vless://"):
            return vless_to_outbound(node)
        if node.startswith("trojan://"):
            return trojan_to_outbound(node)
        if node.startswith("ss://"):
            return ss_to_outbound(node)
    except Exception:
        pass
    return None


# ---------------- 6. 节点 -> Clash proxy ----------------

def vmess_to_clash(node: str):
    info = json.loads(b64_decode_loose(node[8:]) or "")
    host = str(info.get("add", "")).strip()
    if not host or not info.get("id"):
        return None
    net = info.get("net", "tcp")
    tls_on = (info.get("tls", "") or "").lower() == "tls"
    p = {"name": node_name(node), "type": "vmess", "server": host,
         "port": int(info.get("port", 443)), "uuid": info["id"],
         "alterId": int(info.get("aid", 0)),
         "cipher": info.get("scy", "auto"), "udp": True}
    if tls_on:
        p["tls"] = True
        p["servername"] = info.get("sni") or info.get("host") or host
        p["skip-cert-verify"] = False
    if net == "ws":
        p["network"] = "ws"
        ws = {"path": info.get("path", "/")}
        if info.get("host"):
            ws["headers"] = {"Host": info["host"]}
        p["ws-opts"] = ws
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": info.get("path", "")}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        h2 = {"path": info.get("path", "/")}
        if info.get("host"):
            h2["host"] = [info["host"]]
        p["h2-opts"] = h2
    else:
        p["network"] = "tcp"
    return p


def vless_to_clash(node: str):
    u = urlparse(node)
    if not u.hostname or not u.username:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    sec = q.get("security", "none")
    p = {"name": node_name(node), "type": "vless", "server": u.hostname,
         "port": u.port or 443, "uuid": u.username, "udp": True}
    if sec == "tls":
        p["tls"] = True
        p["servername"] = q.get("sni") or u.hostname
        p["skip-cert-verify"] = q.get("allowInsecure", "0") == "1"
    elif sec == "reality":
        p["tls"] = True
        p["servername"] = q.get("sni", "")
        p["reality-opts"] = {"public-key": q.get("pbk", ""),
                             "short-id": q.get("sid", "")}
        p["client-fingerprint"] = q.get("fp", "chrome")
    if q.get("flow"):
        p["flow"] = q["flow"]

    net = q.get("type", "tcp")
    if net == "ws":
        p["network"] = "ws"
        ws = {"path": q.get("path", "/")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        p["ws-opts"] = ws
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    elif net in ("h2", "http"):
        p["network"] = "h2"
        h2 = {"path": q.get("path", "/")}
        if q.get("host"):
            h2["host"] = [q["host"]]
        p["h2-opts"] = h2
    return p


def trojan_to_clash(node: str):
    u = urlparse(node)
    if not u.hostname or not u.username:
        return None
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    p = {"name": node_name(node), "type": "trojan", "server": u.hostname,
         "port": u.port or 443, "password": u.username, "udp": True,
         "sni": q.get("sni") or u.hostname,
         "skip-cert-verify": q.get("allowInsecure", "0") == "1"}
    net = q.get("type", "tcp")
    if net == "ws":
        p["network"] = "ws"
        ws = {"path": q.get("path", "/")}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        p["ws-opts"] = ws
    elif net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return p


def ss_to_clash(node: str):
    parsed = parse_ss(node)
    if not parsed:
        return None
    method, password, host, port = parsed
    return {"name": node_name(node), "type": "ss", "server": host, "port": port,
            "cipher": method, "password": password, "udp": True}


def node_to_clash(node: str):
    try:
        if node.startswith("vmess://"):
            return vmess_to_clash(node)
        if node.startswith("vless://"):
            return vless_to_clash(node)
        if node.startswith("trojan://"):
            return trojan_to_clash(node)
        if node.startswith("ss://"):
            return ss_to_clash(node)
    except Exception:
        pass
    return None


# ---------------- 7. 真实协议测试（多 URL 交叉验证） ----------------

def _wait_port(port: int, timeout: float = 1.5) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except Exception:
            time.sleep(0.05)
    return False


def real_test(node: str, xray_bin: str):
    outbound = node_to_outbound(node)
    if not outbound:
        return None

    local_port = random.randint(20000, 60000)
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port,
                      "protocol": "http", "settings": {}}],
        "outbounds": [outbound],
    }
    fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="xc_")
    proc = None
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f)
        proc = subprocess.Popen([xray_bin, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if not _wait_port(local_port, timeout=1.5):
            return None

        proxies = {"http": f"http://127.0.0.1:{local_port}",
                   "https": f"http://127.0.0.1:{local_port}"}

        def probe(url):
            t0 = time.perf_counter()
            try:
                r = requests.get(url, proxies=proxies, timeout=REAL_TIMEOUT,
                                 headers={"User-Agent": UA})
                if r.status_code in (200, 204):
                    return (time.perf_counter() - t0) * 1000
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=len(TEST_URLS)) as ex:
            results = list(ex.map(probe, TEST_URLS))

        ok = [r for r in results if r is not None]
        if len(ok) >= MIN_PROBE_PASS:
            # 用通过样本的平均延迟，更稳
            return node, sum(ok) / len(ok)
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.unlink(cfg_path)
        except Exception:
            pass
    return None


# ---------------- 8. Clash YAML 输出 ----------------

def yaml_str(s) -> str:
    return json.dumps(str(s), ensure_ascii=False)


def dedupe_names(proxies):
    seen = {}
    for p in proxies:
        n = p["name"]
        if n in seen:
            seen[n] += 1
            p["name"] = f"{n} #{seen[n]}"
        else:
            seen[n] = 1
    return proxies


def to_clash_yaml(proxies):
    names = [p["name"] for p in proxies]
    lines = [
        "# 自动生成，请勿手动修改",
        "port: 7890",
        "socks-port: 7891",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "",
        "proxies:",
    ]
    for p in proxies:
        lines.append(f"  - name: {yaml_str(p['name'])}")
        for k, v in p.items():
            if k == "name":
                continue
            lines.extend(_emit_field(k, v, indent=4))

    lines.append("")
    lines.append("proxy-groups:")
    lines.append("  - name: Proxy")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - Auto")
    lines.append("      - DIRECT")
    for n in names:
        lines.append(f"      - {yaml_str(n)}")
    lines.append("  - name: Auto")
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for n in names:
        lines.append(f"      - {yaml_str(n)}")

    lines.append("")
    lines.append("rules:")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,Proxy")
    lines.append("")
    return "\n".join(lines)


def _emit_field(k, v, indent):
    pad = " " * indent
    out = []
    if isinstance(v, bool):
        out.append(f"{pad}{k}: {str(v).lower()}")
    elif isinstance(v, (int, float)):
        out.append(f"{pad}{k}: {v}")
    elif isinstance(v, str):
        out.append(f"{pad}{k}: {yaml_str(v)}")
    elif isinstance(v, list):
        out.append(f"{pad}{k}:")
        for item in v:
            out.append(f"{pad}  - {yaml_str(item)}")
    elif isinstance(v, dict):
        out.append(f"{pad}{k}:")
        for k2, v2 in v.items():
            out.extend(_emit_field(k2, v2, indent + 2))
    else:
        out.append(f"{pad}{k}: {yaml_str(v)}")
    return out


# ---------------- 9. 主流程 ----------------

def main():
    session = make_session()
    cache = load_cache()

    # 1. 抓源
    print("开始并发抓取节点列表...")
    raw_nodes = fetch_raw_nodes(session)
    print(f"去重后共 {len(raw_nodes)} 个节点")

    if not raw_nodes:
        return

    # 2. TCP 预筛
    print(f"TCP 预筛中 (并发 {TCP_WORKERS})...")
    tcp_alive = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        for r in ex.map(tcp_check, raw_nodes):
            if r:
                tcp_alive.append(r)
    print(f"TCP 存活 {len(tcp_alive)} 个")

    if not tcp_alive:
        return

    # 3. 按缓存评分排序（优先测历史成功率高的）
    tcp_alive.sort(key=lambda x: -node_score(x[0], cache))
    candidates = tcp_alive[:REAL_MAX_NODES]

    # 4. 真实测试
    xray_bin = ensure_xray()
    print(f"真实协议测试 {len(candidates)} 个节点 (并发 {REAL_WORKERS}, "
          f"交叉验证 {len(TEST_URLS)} 个 URL, 需通过 {MIN_PROBE_PASS} 个)...")

    real_alive = []
    with ThreadPoolExecutor(max_workers=REAL_WORKERS) as ex:
        futs = {ex.submit(real_test, n, xray_bin): n for n, _ in candidates}
        done = 0
        for fut in as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                real_alive.append(r)
            if done % 25 == 0:
                print(f"  已测 {done}/{len(candidates)}，通过 {len(real_alive)}")

    real_alive.sort(key=lambda x: x[1])
    print(f"真实可用节点: {len(real_alive)}")

    # 5. 更新缓存
    success_map = {n: ms for n, ms in real_alive}
    now = int(time.time())
    for node, _ in candidates:
        info = cache.setdefault(node, {"success": 0, "fail": 0})
        if node in success_map:
            info["success"] = info.get("success", 0) + 1
            info["last_success"] = now
            info["last_latency"] = success_map[node]
        else:
            info["fail"] = info.get("fail", 0) + 1
    save_cache(cache)

    # 6. 导出订阅
    plain = "\n".join(n for n, _ in real_alive)
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain.encode()).decode())
    with open("sub_plain.txt", "w", encoding="utf-8") as f:
        f.write(plain)
    with open("sub_latency.txt", "w", encoding="utf-8") as f:
        for n, ms in real_alive:
            f.write(f"{ms:7.1f}ms  {n}\n")

    # 7. 导出 Clash
    clash_proxies = []
    for n, _ in real_alive:
        p = node_to_clash(n)
        if p:
            clash_proxies.append(p)
    clash_proxies = dedupe_names(clash_proxies)
    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write(to_clash_yaml(clash_proxies))

    print("已更新: sub.txt / sub_plain.txt / sub_latency.txt / clash.yaml / node_cache.json")


if __name__ == "__main__":
    main()
