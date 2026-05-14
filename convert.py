import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
import hashlib
from collections import defaultdict

# ==================== 配置区 ====================
CHANNEL_MARK = "@zmxooo"
CACHE_FILE = 'ip_cache.json'

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "俄罗斯": "🇷🇺",
    "法国": "🇫🇷", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺"
}

# 加载本地缓存以应对万次运行
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            IP_CACHE = json.load(f)
    except: IP_CACHE = {}
else: IP_CACHE = {}

def save_ip_cache():
    with open(CACHE_FILE, 'w', encoding='utf-8') as f:
        json.dump(IP_CACHE, f, ensure_ascii=False, indent=2)

# ==================== 1. 强化识别逻辑 ====================
def get_final_label(server: str, remarks: str = "") -> str:
    remarks = urllib.parse.unquote(str(remarks)).lower().strip()
    server = str(server).lower()

    # 优先级 1: 备注关键词识别
    meta = [
        ("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台湾|台灣"),
        ("美国", r"us|united|america|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("俄罗斯", r"ru|russia|俄罗斯")
    ]
    for name, pattern in meta:
        if re.search(pattern, remarks):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 优先级 2: 域名关键词识别
    for name, pattern in meta:
        if re.search(pattern, server):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 优先级 3: 带缓存的 IP 查询
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE: return IP_CACHE[server]
        try:
            time.sleep(0.4) # 万次运行建议配合本地 mmdb 库，API 需限速
            resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
            if resp.get("status") == "success":
                country = resp.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[server] = label
                return label
        except: pass
    return "🧿 其他地区"

# ==================== 2. 防错解析器 (修复 KeyError) ====================
def parse_link(link: str):
    try:
        link = link.strip()
        if not link or len(link) < 10: return None
        
        main_part = link.split('#')[0]
        orig_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""

        # --- VMess 专项修复 ---
        if link.startswith('vmess://'):
            b64_data = main_part[8:]
            pad = len(b64_data) % 4
            if pad: b64_data += '=' * (4 - pad)
            d = json.loads(base64.b64decode(b64_data).decode('utf-8', 'ignore'))
            node = {
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port", 443)),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": d.get("tls") == "tls", "network": d.get("net", "tcp"),
                "servername": d.get("sni") or d.get("host", ""),
                "original_remarks": d.get("ps", "")
            }
            if d.get("net") == "ws":
                node["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", "")}}
            return node

        # --- 通用协议处理 ---
        # 兼容简写并确保协议头正确
        norm_link = main_part.replace("hy2://", "hysteria2://", 1) if main_part.startswith("hy2://") else main_part
        u = urllib.parse.urlparse(norm_link)
        qs = urllib.parse.parse_qs(u.query)
        params = {k: v[0] for k, v in qs.items()}

        # 核心：必须先初始化 type，防止 KeyError
        node = {
            "type": u.scheme,
            "server": u.hostname,
            "port": u.port or 443,
            "original_remarks": orig_remarks
        }

        if u.scheme == "hysteria2":
            node.update({
                "password": u.username or u.password,
                "auth": u.username or u.password,
                "sni": params.get("sni", u.hostname),
                "skip-cert-verify": True, "alpn": ["h3"]
            })
        elif u.scheme == "vless":
            node.update({
                "uuid": u.username, "cipher": "auto", "tls": True, "udp": True,
                "servername": params.get("sni", ""), "network": params.get("type", "tcp"),
                "reality-opts": {"public-key": params.get("pbk"), "short-id": params.get("sid")} if params.get("pbk") else None
            })
        elif u.scheme == "trojan":
            node.update({"password": u.username, "sni": params.get("sni", u.hostname), "tls": True})
        elif u.scheme == "ss":
            node.update({"cipher": "auto", "password": u.username or "", "udp": True})
        
        return node
    except: return None

# ==================== 3. 主逻辑 ====================
def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        raw_lines = list(set([l.strip() for l in f if l.strip()]))

    clash_proxies = []
    final_raw_links = []
    region_groups = defaultdict(list)
    fingerprints = set()

    print(f"🔄 正在处理 {len(raw_lines)} 个节点...")

    for line in raw_lines:
        p = parse_link(line)
        # 严格校验：必须包含 type 且 server 不能为空
        if not p or not p.get("type") or not p.get("server"): 
            continue

        # 唯一性计算 (防御性 key 获取)
        cred = p.get('uuid') or p.get('password') or "none"
        fp = hashlib.md5(f"{p['type']}{p['server']}{p['port']}{cred}".encode()).hexdigest()
        
        if fp in fingerprints: continue
        fingerprints.add(fp)

        # 识别位置
        label = get_final_label(p['server'], p.get('original_remarks', ''))
        region_groups[label].append(p)

    # 排序重命名
    for label in sorted(region_groups.keys()):
        for idx, p in enumerate(region_groups[label], 1):
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            
            # Base64 订阅输出
            l_type = "hy2" if p['type'] == "hysteria2" else p['type']
            final_raw_links.append(f"{l_type}://{p['server']}:{p['port']}#{urllib.parse.quote(new_name)}")

            # Clash Proxy 输出
            cp = {k: v for k, v in p.items() if v is not None and k != "original_remarks"}
            cp["name"] = new_name
            clash_proxies.append(cp)

    # 写入 config.yaml
    if clash_proxies:
        sorted_labels = sorted(region_groups.keys())
        conf = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + sorted_labels},
                {"name": "⚡ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [x["name"] for x in clash_proxies]}
            ]
        }
        for label in sorted_labels:
            conf["proxy-groups"].append({
                "name": label, "type": "url-test", "proxies": [x["name"] for x in clash_proxies if x["name"].startswith(label)]
            })
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

    # 写入 index.html (Base64)
    if final_raw_links:
        b64_str = base64.b64encode("\n".join(final_raw_links).encode()).decode()
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(b64_str)

    save_ip_cache()
    print(f"✨ 处理完成！当前有效节点: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
