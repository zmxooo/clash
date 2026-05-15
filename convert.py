import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

# --- [配置区] ---
# 统一的后缀字符
FIXED_SUFFIX = "zmxooo"
IP_CACHE = {}

# 预判逻辑：确保识别率的关键规则
RULES = [
    ("香港", r"HK|HONGKONG|香港|廣港|CMI|HKT|PCCW|HGC"),
    ("台湾", r"TW|TAIWAN|台湾|台灣|彰化|台北"),
    ("日本", r"JP|JAPAN|日本|东京|大阪|NTT"),
    ("韩国", r"KR|KOREA|韩国|韓國|首尔"),
    ("新加坡", r"SG|SINGAPORE|新加坡"),
    ("美国", r"US|USA|UNITED STATES|美国|美國|洛杉矶"),
    ("英国", r"UK|GB|UNITED KINGDOM|英国"),
    ("德国", r"DE|GERMANY|德国"),
    ("俄罗斯", r"RU|RUSSIA|俄罗斯"),
    ("越南", r"VN|VIETNAM|越南"),
    ("泰国", r"TH|THAILAND|泰国")
]

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "美国": "🇺🇸", "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", 
    "越南": "🇻🇳", "泰国": "🇹🇭", "其它": "🌍"
}

def get_region(server, remarks):
    """
    精准识别逻辑：
    只要备注里有地区词，绝对不去查 IP，保证出口地准确。
    """
    rem_text = urllib.parse.unquote(str(remarks)).upper()
    for name, pattern in RULES:
        if re.search(pattern, rem_text):
            return name
            
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.5) 
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in c:
                    IP_CACHE[server] = name
                    return name
            return c
    except: pass
    return "其它"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    # 用于存放分类后的节点，以便生成序号
    classified_nodes = defaultdict(list)
    
    # 第一步：解析并按地区归类
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

    final_links = []
    clash_proxies = []

    # 第二步：按地区生成统一后缀和序号
    sorted_regions = sorted(classified_nodes.keys())
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            # 统一备注格式：🇭🇰香港 zmxooo1
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                if link.startswith('vmess://'):
                    b64 = link[8:].split('#')[0]
                    d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
                    d["ps"] = new_name
                    new_b64 = base64.b64encode(json.dumps(d, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                    final_links.append(f"vmess://{new_b64}")
                    
                    # Clash Proxy
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
                    base_part = link.split('#')[0]
                    final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")
                    
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname, "port": u.port or 443, "udp": True}
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({"type": "hysteria2", "password": u.username, "up": 20, "down": 100, "skip-cert-verify": True})
                        clash_proxies.append(p)
                    elif u.scheme == "vless":
                        p.update({"type": "vless", "uuid": u.username, "tls": True, "skip-cert-verify": True})
                        clash_proxies.append(p)
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        try:
          
