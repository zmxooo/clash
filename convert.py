import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

# --- [配置区] ---
CHANNEL_MARK = "@zmxooo"
IP_CACHE = {}

# 预知问题 1：地区识别不准。方案：极其详尽的正则库，覆盖营运商和常用中转名
RULES = [
    ("香港", r"HK|HONGKONG|香港|HGC|HKT|PCCW|廣港|WTT|CMI"),
    ("台湾", r"TW|TAIWAN|台湾|CHT|彰化|台北|台"),
    ("日本", r"JP|JAPAN|日本|东京|大阪|東京|大阪|NTT|KDDI|SOFTBANK"),
    ("韩国", r"KR|KOREA|韩国|首尔|首爾|SK|KT|LG"),
    ("新加坡", r"SG|SINGAPORE|新加坡|LEASWEWEB"),
    ("美国", r"US|USA|UNITED STATES|美国|洛杉矶|圣何塞|西雅图|波特兰|GIA|NCP"),
    ("英国", r"UK|GB|UNITED KINGDOM|英国|伦敦"),
    ("德国", r"DE|GERMANY|德国|法兰克福"),
    ("法国", r"FR|FRANCE|法国"),
    ("俄罗斯", r"RU|RUSSIA|俄罗斯|伯力|莫斯科|KHB|MOW"),
    ("越南", r"VN|VIETNAM|越南"),
    ("泰国", r"TH|THAILAND|泰国"),
    ("菲律宾", r"PH|PHILIPPINES|菲律宾"),
    ("马来西亚", r"MY|MALAYSIA|马来西亚"),
    ("土耳其", r"TR|TURKEY|土耳其"),
    ("澳大利亚", r"AU|AUSTRALIA|澳大利亚|澳洲")
]

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "美国": "🇺🇸", "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", 
    "越南": "🇻🇳", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", "土耳其": "🇹🇷", 
    "澳大利亚": "🇦🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "巴西": "🇧🇷", "印度": "🇮🇳"
}

def get_final_label(server, remarks):
    """
    预知问题 2：IP判断不准。
    解决方案：备注正则 > 域名后缀 > IP API 模糊匹配。
    """
    rem_text = urllib.parse.unquote(str(remarks)).upper()
    server_low = server.lower()

    # 1. 优先根据备注关键词预判（最准确，解决中转出口问题）
    for name, pattern in RULES:
        if re.search(pattern, rem_text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 2. 根据域名后缀预判（极速，解决 API 频率限制）
    suffix_map = {'.tw': '台湾', '.jp': '日本', '.hk': '香港', '.sg': '新加坡', '.kr': '韩国', '.us': '美国'}
    for suffix, name in suffix_map.items():
        if server_low.endswith(suffix):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 3. 最后求助 API（加入缓存防止封禁）
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.15) 
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            country_api = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in country_api: # 模糊匹配 API 返回的长字符串
                    label = f"{EMOJI_MAP[name]} {name}"
                    IP_CACHE[server] = label
                    return label
            return f"🌍 {country_api}"
    except: pass
    return "🧿 其它地区"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """
    预知问题 3：字段缺失导致无法导入。
    解决方案：补全 VLESS/Hy2/VMess 在 Clash 中的所有必填项。
    """
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            d = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
            label = get_final_label(d.get("add"), d.get("ps", ""))
            proxy = {
                "name": new_name, "type": "vmess", "server": str(d.get("add")),
                "port": int(d.get("port", 443)), "uuid": str(d.get("id")),
                "alterId": int(d.get("aid", 0)), "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": d.get("net", "tcp")
            }
            if d.get("net") == "ws":
                proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
            # 还原订阅链接使用的原始 VMess 字符串
            return label, proxy, link

        elif "://" in link:
            u = urllib.parse.urlparse(link)
            protocol = u.scheme
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            label = get_final_label(u.hostname, old_remarks)
            
            # 基础结构
            proxy = {"name": new_name, "server": u.hostname, "port": u.port if u.port else 443, "udp": True}

            if protocol in ["hysteria2", "hy2"]:
                proxy.update({"type": "hysteria2", "password": u.username, "up": 20, "down": 100, "skip-cert-verify": True})
            elif protocol == "vless":
                proxy.update({"type": "vless", "uuid": u.username, "tls": True, "skip-cert-verify": True})
            elif protocol in ["ss", "shadowsocks"]:
                proxy["type"] = "ss"
                try:
                    user_info = base64.b64decode(fix_base64(u.username)).decode().split(':')
                    proxy["cipher"], proxy["password"] = user_info[0], user_info[1]
                except: return label, None, link
            else:
                return label, None, link # 其余协议只进订阅，不进 Clash

            return label, proxy, link
    except: pass
    return None, None, None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    items = []
    for l in links:
        label, _, _ = rebuild_node(l, "TEMP")
        if label: items.append({"label": label, "link": l})

    items.sort(key=lambda x: x["label"])
    final_links, clash_proxies, counters = [], [], defaultdict(int)

    for i in items:
        label = i["label"]
        counters[label] += 1
        name = f"{label} {counters[label]:02d} | {CHANNEL_MARK}"
        _, proxy, original_link = rebuild_node(i["link"], name)
        
        # 处理 index.html (Base64) 使用的链接
        base_part = original_link.split('#')[0]
        final_links.append(f"{base_part}#{urllib.parse.quote(name)}")
        if proxy: clash_proxies.append(proxy)

    # 1. 写入 index.html (维持 Base64 逻辑)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # 预知问题 4：没分组没节点。方案：强制注入策略组结构
    if clash_proxies:
        p_names = [p["name"] for p in clash_proxies]
        full_yaml = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + p_names},
                {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": p_names}
            ],
            "rules": ["MATCH,🚀 节点选择"]
        }
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(full_yaml, f, allow_unicode=True, sort_keys=False)
        print(f"成功！已处理 {len(clash_proxies)} 个 Clash 节点。")

if __name__ == "__main__":
    main()
