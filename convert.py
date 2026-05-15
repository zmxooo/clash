import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

# --- [保持你原有的配置逻辑] ---
FIXED_SUFFIX = "zmxooo"
IP_CACHE = {}

# 强化识别库：这是解决你提到的“正确率不足 60%”的关键
# 只要备注里有这些词，就直接判定地区，不再查 IP，防止中转节点识别错误
RULES = [
    ("香港", r"HK|HONGKONG|香港|廣港|CMI|HKT|PCCW|HGC|WTT"),
    ("台湾", r"TW|TAIWAN|台湾|台灣|彰化|台北|CHT"),
    ("日本", r"JP|JAPAN|日本|东京|大阪|東京|大阪|NTT|KDDI"),
    ("韩国", r"KR|KOREA|韩国|韓國|首尔|首爾|SK|KT"),
    ("新加坡", r"SG|SINGAPORE|新加坡|AWS-SG"),
    ("美国", r"US|USA|UNITED STATES|美国|美國|洛杉矶|圣何塞|GIA"),
    ("英国", r"UK|GB|UNITED KINGDOM|英国|英國|伦敦"),
    ("德国", r"DE|GERMANY|德国|德國|法兰克福"),
    ("俄罗斯", r"RU|RUSSIA|俄罗斯|俄羅斯|伯力|莫斯科"),
    ("越南", r"VN|VIETNAM|越南"),
    ("泰国", r"TH|THAILAND|泰国")
]

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "美国": "🇺🇸", "英国": "🇬🇧", "德国": "🇩🇪", "俄罗斯": "🇷🇺", "越南": "🇻🇳", "泰国": "🇹🇭", "其它": "🌍"
}

def get_region(server, remarks):
    """精准识别逻辑：备注优先，彻底解决识别不准问题"""
    rem_text = urllib.parse.unquote(str(remarks)).upper()
    # 1. 备注关键词匹配
    for name, pattern in RULES:
        if re.search(pattern, rem_text):
            return name
    # 2. IP API 保底
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.5) # 防止请求过快
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in c:
                    IP_CACHE[server] = name
                    return name
            return c
    except:
        pass
    return "其它"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    # 按地区归类，以便后续生成 zmxooo1, zmxooo2...
    classified_nodes = defaultdict(list)
    for link in links:
        try:
            host, raw_rem = "", ""
            if link.startswith('vmess://'):
                b64 = link[8:].split('#')[0]
                d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
                host, raw_rem = d.get("add"), d.get("ps")
            else:
                u = urllib.parse.urlparse(link)
                host = u.hostname
                raw_rem = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            region = get_region(host, raw_rem)
            classified_nodes[region].append(link)
        except:
            continue

    final_links, clash_proxies = [], []
    sorted_regions = sorted(classified_nodes.keys())
    
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            # 还原你原本的格式逻辑：[国旗][国家] zmxooo[序号]
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                # --- 修正后的解析块，确保缩进正确 ---
                if link.startswith('vmess://'):
                    b64 = link[8:].split('#')[0]
                    d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
                    d["ps"] = new_name
                    new_b64 = base64.b64encode(json.dumps(d, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                    final_links.append(f"vmess://{new_b64}")
                    
                    proxy = {
                        "name": new_name, "type": "vmess", "server": d["add"], "port": int(d["port"]),
                        "uuid": d["id"], "alterId": int(d.get("aid", 0)), "cipher": "auto",
                        "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                        "network": d.get("net", "tcp"), "skip-cert-verify": True
                    }
                    if d.get("net") == "ws":
                        proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
                    clash_proxies.append(proxy)
                    
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname, "port": u.port or 443, "udp": True}
                    if u.scheme in ["hy2", "hysteria2"]:
                        # 补全 Mihomo 内核要求的 up/down
                        p.update({"type": "hysteria2", "password": u.username, "up": "20 Mbps", "down": "100 Mbps", "skip-cert-verify": True})
                        clash_proxies.append(p)
                    elif u.scheme == "vless":
                        p.update({"type": "vless", "uuid": u.username, "tls": True, "skip-cert-verify": True})
                        clash_proxies.append(p)
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        try:
                            info = base64.b64decode(fix_base64(u.username)).decode().split(':')
                            p["cipher"], p["password"] = info[0], info[1]
                            clash_proxies.append(p)
                        except: pass
                    
                    final_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}")
            except:
                continue

    # 生成 index.html (Base64)
    if final_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # 生成 config.yaml (Clash)
    if clash_proxies:
        p_names = [p["name"] for p in clash_proxies]
        conf = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + p_names},
                {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": p_names}
            ],
            "rules": ["MATCH,🚀 节点选择"]
        }
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
