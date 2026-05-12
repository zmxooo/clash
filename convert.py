import base64, json, yaml, os, re, requests, time
from urllib.parse import urlparse, parse_qs, unquote

# 配置常量
HEADERS = {"User-Agent": "ClashMeta"}
MARK = "@zmxooo"

def safe_b64decode(data):
    """加固型 Base64 解码，支持 URLSafe 格式"""
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except: return ""

def get_region(text):
    """地域识别逻辑"""
    text = unquote(str(text)).lower()
    rules = {
        "🇭🇰 香港节点": r"香港|hk|hongkong|🇭🇰",
        "🇹🇼 台湾节点": r"台湾|tw|taiwan|🇹🇼",
        "🇯🇵 日本节点": r"日本|jp|japan|🇯🇵",
        ("🇸🇬 新加坡节点"): r"新加坡|sg|singapore|🇸🇬",
        "🇰🇷 韩国节点": r"韩国|kr|korea|🇰🇷",
        "🇺🇸 美国节点": r"美国|us|unitedstates|america|🇺🇸",
        "🇬🇧 英国节点": r"英国|uk|britain|🇬🇧",
        "🇩🇪 德国节点": r"德国|de|germany|🇩🇪",
        "🇻🇳 越南节点": r"越南|vn|vietnam|🇻🇳",
    }
    for name, rule in rules.items():
        if re.search(rule, text): return name
    return "🧿 其它地区"

# --- 核心解析模块 ---
def parse_vmess(link):
    try:
        j = json.loads(safe_b64decode(link.replace("vmess://", "")))
        return {"type": "vmess", "server": j["add"], "port": int(j["port"]), "uuid": j["id"], "alterId": 0, "cipher": "auto", "udp": True, "tls": str(j.get("tls")).lower() in ["tls", "true"], "skip-cert-verify": True, "network": j.get("net", "tcp")}
    except: return None

def parse_vless(link):
    try:
        u = urlparse(link); q = parse_qs(u.query)
        p = {"type": "vless", "server": u.hostname, "port": int(u.port or 443), "uuid": u.username, "cipher": "auto", "udp": True, "tls": True, "skip-cert-verify": True, "servername": (q.get("sni") or [u.hostname])[0]}
        if q.get("security", [""])[0] == "reality":
            p["reality-opts"] = {"public-key": q.get("pbk", [""])[0], "short-id": q.get("sid", [""])[0]}
        return p
    except: return None

def parse_trojan(link):
    try:
        u = urlparse(link); q = parse_qs(u.query)
        return {"type": "trojan", "server": u.hostname, "port": int(u.port or 443), "password": u.username, "udp": True, "skip-cert-verify": True, "sni": (q.get("sni") or [u.hostname])[0]}
    except: return None

def parse_ss(link):
    try:
        content = link.replace("ss://", "").split('#')[0]
        if "@" not in content: content = safe_b64decode(content)
        left, right = content.split("@")
        method, pwd = (left if ":" in left else safe_b64decode(left)).split(":", 1)
        srv, port = right.split(":")
        return {"type": "ss", "server": srv, "port": int(port), "cipher": method, "password": pwd, "udp": True}
    except: return None

def parse_link(link):
    if "vmess://" in link: return parse_vmess(link)
    if "vless://" in link: return parse_vless(link)
    if "trojan://" in link: return parse_trojan(link)
    if "ss://" in link: return parse_ss(link)
    return None

def fetch_sub(url):
    """支持 YAML/Base64/明文全格式抓取"""
    try:
        r = requests.get(url, timeout=15, headers=HEADERS)
        txt = r.text.strip()
        if "proxies:" in txt:
            return yaml.safe_load(txt).get("proxies", [])
        decoded = safe_b64decode(txt)
        return re.findall(r"(?:vmess|vless|trojan|ss)://[^\s#\"'>]+", decoded if decoded else txt)
    except: return []

def main():
    if not os.path.exists("nodes.txt"): return print("❌ nodes.txt 不存在")
    with open("nodes.txt", "r", encoding="utf-8") as f:
        subs = [x.strip() for x in f if x.strip()]

    all_proxies, reg_map = [], {}
    print(f"🚀 开始处理 {len(subs)} 个订阅源...")

    for sub in subs:
        data = fetch_sub(sub)
        for item in data:
            p = item if isinstance(item, dict) else parse_link(item)
            if p and p.get("server"):
                # 确定地域并重命名
                name_to_check = p.get("name", "") or p.get("server", "")
                region = get_region(name_to_check)
                if region not in reg_map: reg_map[region] = []
                
                new_name = f"{region} {MARK} {len(reg_map[region]) + 1:02d}"
                p["name"] = new_name
                reg_map[region].append(new_name)
                all_proxies.append(p)

    if not all_proxies: return print("⚠️ 未抓取到有效节点")

    # --- Clash 配置生成 ---
    target_regs = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🇬🇧 英国节点", "🇩🇪 德国节点", "🇻🇳 越南节点", "🧿 其它地区"]
    active_regs = [r for r in target_regs if reg_map.get(r)]
    
    region_groups = [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": reg_map[r]} for r in active_regs]
    
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "ipv6": True,
        "tun": {"enable": True, "stack": "mixed", "auto-route": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]},
        "proxies": all_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + active_regs + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p["name"] for p in all_proxies]},
            {"name": "🤖 智能 AI", "type": "select", "proxies": ["🇺🇸 美国节点", "🇸🇬 新加坡节点", "🇯🇵 日本节点", "🚀 节点选择"]}
        ] + region_groups,
        "rules": [
            "DOMAIN-SUFFIX,openai.com,🤖 智能 AI",
            "DOMAIN-SUFFIX,chatgpt.com,🤖 智能 AI",
            "DOMAIN-SUFFIX,anthropic.com,🤖 智能 AI",
            "DOMAIN-SUFFIX,google.com,🚀 节点选择",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    
    print(f"✨ 搞定！已从所有源抓取并去重处理了 {len(all_proxies)} 个节点。")
    print(f"📂 配置文件: {os.path.abspath('config.yaml')}")

if __name__ == "__main__":
    main()
