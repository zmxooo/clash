import base64
import json
import urllib.parse
import os
import re
import yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

# ==================== 1. 严格保留脚本 A 的解码语法 ====================
def parse_vmess_b64(b64_part):
    if not isinstance(b64_part, str):
        b64_part = str(b64_part)
    # 核心修复：只保留 Base64 字符，剔除备注等杂质
    b64_part = re.sub(r'[^a-zA-Z0-9+/=_-]', '', b64_part.split('#')[0].split('?')[0])
    b64_part = b64_part.replace('-', '+').replace('_', '/')
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except:
        return b""

def safe_int(val, default=443):
    try:
        if isinstance(val, int): return val
        clean_val = re.sub(r'\D', '', str(val))
        return int(clean_val) if clean_val else default
    except: return default

def get_final_label(server, remarks=""):
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台"), ("美国", r"us|america|美国"), ("日本", r"jp|japan|日本"), ("新加坡", r"sg|singapore|新")]
    for name, pattern in meta:
        if re.search(pattern, text): return f"🌍 {name}"
    return "🧿 其他地区"

# ==================== 2. 全协议解析 (Hy2 修复补丁) ====================
def parse_link(link):
    link = link.strip()
    if not link: return None

    try:
        # --- VMess 逻辑 (完全回归脚本 A) ---
        if link.startswith('vmess://'):
            b64_part = link[8:]
            raw_data = parse_vmess_b64(b64_part)
            if not raw_data: return None
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "type": "vmess", "server": data.get("add"), 
                "port": data.get("port"), "uuid": data.get("id"),
                "aid": data.get("aid", 0), "net": data.get("net"),
                "path": data.get("path"), "host": data.get("host"),
                "tls": data.get("tls"), "remarks": data.get("ps", "")
            }

        # --- Hy2 逻辑 (移植脚本 B 的修复成果) ---
        elif link.startswith(('hy2://', 'hysteria2://')):
            u = urllib.parse.urlparse(link)
            return {
                "type": "hysteria2", "server": u.hostname, "port": u.port or 443,
                "password": u.username, "sni": u.hostname, "remarks": u.fragment
            }
            
        # --- 其他协议 ---
        elif link.startswith(('ss://', 'trojan://', 'vless://')):
            u = urllib.parse.urlparse(link)
            return {
                "type": u.scheme, "server": u.hostname, "port": u.port or 443,
                "password": u.username, "remarks": u.fragment
            }
    except: return None
    return None

# ==================== 3. 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [l.strip() for l in f if l.strip()]

    clash_proxies = []
    region_count = defaultdict(int)

    for line in lines:
        p = parse_link(line)
        if not p: continue

        label = get_final_label(p.get("server"), p.get("remarks", ""))
        region_count[label] += 1
        name = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"

        if p["type"] == "vmess":
            clash_proxies.append({
                "name": name, "type": "vmess", "server": p["server"],
                "port": safe_int(p["port"]), "uuid": p["uuid"], "alterId": safe_int(p["aid"]),
                "cipher": "auto", "tls": p["tls"] in ["tls", True, 1],
                "network": p["net"] or "tcp",
                "ws-opts": {"path": p["path"], "headers": {"Host": p["host"]}} if p["net"] == "ws" else None
            })
        elif p["type"] == "hysteria2":
            clash_proxies.append({
                "name": name, "type": "hysteria2", "server": p["server"],
                "port": safe_int(p["port"]), "password": p["password"],
                "sni": p["sni"], "skip-cert-verify": True, "alpn": ["h3"]
            })
        else:
            clash_proxies.append({
                "name": name, "type": p["type"], "server": p["server"],
                "port": safe_int(p["port"]), "password": p["password"], "uuid": p["password"]
            })

    # 输出结果
    res = {"proxies": clash_proxies, "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies]}]}
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(res, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
