import base64, json, yaml, os, re, requests, time
from urllib.parse import urlparse, parse_qs, unquote

# 配置常量
HEADERS = {"User-Agent": "ClashMeta"}
MARK = "@zmxooo"

def safe_b64decode(data):
    try:
        data = data.strip().replace('-', '+').replace('_', '/')
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except: return ""

def get_region(text):
    text = unquote(str(text)).lower()
    rules = {
        "🇭🇰 香港节点": r"香港|hk|hongkong|🇭🇰",
        "🇹🇼 台湾节点": r"台湾|tw|taiwan|🇹🇼",
        "🇯🇵 日本节点": r"日本|jp|japan|🇯🇵",
        "🇸🇬 新加坡节点": r"新加坡|sg|singapore|🇸🇬",
        "🇰🇷 韩国节点": r"韩国|kr|korea|🇰🇷",
        "🇺🇸 美国节点": r"美国|us|unitedstates|america|🇺🇸",
        "🇬🇧 英国节点": r"英国|uk|britain|🇬🇧",
        "🇩🇪 德国节点": r"德国|de|germany|🇩🇪",
        "🇻🇳 越南节点": r"越南|vn|vietnam|🇻🇳",
    }
    for name, rule in rules.items():
        if re.search(rule, text): return name
    return "🧿 其它地区"

def parse_link(link):
    """解析单体链接：vmess/vless/trojan/ss"""
    try:
        if link.startswith('vmess://'):
            j = json.loads(safe_b64decode(link[8:].split('#')[0]))
            return {"type": "vmess", "server": j["add"], "port": int(j["port"]), "uuid": j["id"], "alterId": 0, "cipher": "auto", "tls": str(j.get("tls")).lower() in ["tls", "true"], "network": j.get("net", "tcp")}
        elif link.startswith(('vless://', 'trojan://')):
            u = urlparse(link); q = parse_qs(u.query)
            p = {"type": "vless" if "vless" in link else "trojan", "server": u.hostname, "port": int(u.port or 443), "uuid": u.username if "vless" in link else None, "password": u.username if "trojan" in link else None, "tls": True, "sni": (q.get("sni") or [u.hostname])[0]}
            return p
        elif link.startswith('ss://'):
            content = link.replace("ss://", "").split('#')[0]
            if "@" not in content: content = safe_b64decode(content)
            left, right = content.split("@")
            method, pwd = (left if ":" in left else safe_b64decode(left)).split(":", 1)
            srv, port = right.rsplit(":", 1)
            return {"type": "ss", "server": srv, "port": int(port), "cipher": method, "password": pwd}
    except: return None

def fetch_content(url):
    """抓取并深度解析：支持YAML/Base64/明文"""
    try:
        r = requests.get(url, timeout=15, headers=HEADERS)
        if r.status_code != 200: return []
        txt = r.text.strip()
        
        # 1. 尝试作为 YAML 解析 (Clash 格式)
        if "proxies:" in txt or url.endswith(('.yaml', '.yml')):
            try:
                data = yaml.safe_load(txt)
                if isinstance(data, dict) and 'proxies' in data:
                    return data['proxies']
            except: pass

        # 2. 尝试作为 Base64 解码后解析
        decoded = safe_b64decode(txt)
        content = decoded if (decoded and "://" in decoded) else txt
        
        # 3. 正则抓取所有链接
        return re.findall(r"(?:vmess|vless|trojan|ss)://[^\s#\"'>]+", content)
    except: return []

def main():
    if not os.path.exists("nodes.txt"): return print("❌ nodes.txt 不存在")
    with open("nodes.txt", "r", encoding="utf-8") as f:
        subs = [x.strip() for x in f if x.strip()]

    all_proxies, reg_map = [], {}
    print(f"🚀 正在从 {len(subs)} 个源抓取节点...")

    for sub in subs:
        data = fetch_content(sub)
        print(f"📡 {sub[:40]}... 找到 {len(data)} 个候选")
        for item in data:
            p = item if isinstance(item, dict) else parse_link(item)
            if isinstance(p, dict) and p.get("server"):
                region = get_region(p.get("name", "") or p.get("server", ""))
                if region not in reg_map: reg_map[region] = []
                p["name"] = f"{region} {MARK} {len(reg_map[region]) + 1:02d}"
                reg_map[region].append(p["name"])
                all_proxies.append(p)

    if not all_proxies: return print("⚠️ 未抓取到任何有效节点，请检查 nodes.txt 中的链接是否有效")

    # 策略组生成
    target_regs = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🇬🇧 英国节点", "🇩🇪 德国节点", "🇻🇳 越南节点", "🧿 其它地区"]
    active_regs = [r for r in target_regs if reg_map.get(r)]
    groups = [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": reg_map[r]} for r in active_regs]
    
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule",
        "tun": {"enable": True, "stack": "mixed", "auto-route": True},
        "proxies": all_proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + active_regs + ["DIRECT"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": [p["name"] for p in all_proxies]}
        ] + groups,
        "rules": ["DOMAIN-SUFFIX,openai.com,🇺🇸 美国节点", "GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"✨ 成功！总计处理节点: {len(all_proxies)}，已保存至 config.yaml")

if __name__ == "__main__":
    main()
