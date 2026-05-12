import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# 1. 增加本地 IP 结果缓存，解决 API 限流导致的“其他地区”
IP_CACHE = {} 

# 2. 极大增强图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", "菲律宾": "🇵🇭"
}

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    
    # 3. 增强正则库，不查 IP 也能识别科威特等地区
    meta = [
        ("香港", r"hk|香港|hongkong"), 
        ("台湾", r"tw|台湾|台灣|taiwan"),
        ("美国", r"us|美国|美國|united states|usa"), 
        ("英国", r"gb|uk|英国|英國"),
        ("韩国", r"kr|韩国|韓國|korea"), 
        ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore"),
        ("科威特", r"kw|kuwait|科威特"),
        ("德国", r"de|germany|德国"),
        ("荷兰", r"nl|netherlands|荷兰")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    # 4. 只有正则没中才查 IP
    if server in IP_CACHE:
        return IP_CACHE[server]

    try:
        # 强制频率保护：每秒查询不超过 1 次
        time.sleep(1.3) 
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}节点"
            IP_CACHE[server] = label # 存入缓存
            return label
    except Exception as e:
        print(f"⚠️ IP查询失败 ({server}): {e}")
    
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        if link.startswith('vmess://'):
            b64_body = link[8:].split('#')[0]
            b64_body += '=' * (-len(b64_body) % 4)
            raw_data = base64.b64decode(b64_body)
            try: decoded_str = raw_data.decode('utf-8')
            except: decoded_str = raw_data.decode('gbk')
            d = json.loads(decoded_str)
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": int(d.get("aid", 0)), "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True, "raw_json": d
            }
        elif link.startswith(('ss://', 'trojan://', 'hy')):
            # 小火箭/V2Box 兼容性：确保备注被识别
            raw_ps = urllib.parse.unquote(u.fragment) if u.fragment else ""
            return {
                "label": get_final_label(u.hostname, raw_ps),
                "type": "other", "link": link, "server": u.hostname
            }
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = list(dict.fromkeys([l.strip() for l in ls if l.strip() and not any(l.startswith(x) for x in ['import','def','git','#'])]))

    region_map = defaultdict(list)
    proxies = []
    final_links = []

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            # 严格遵循你的 ID 自动计数逻辑
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # --- 解决 Base64 订阅不统一 (小火箭/V2Box 专用) ---
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_b64 = base64.b64encode(json.dumps(d, separators=(',', ':')).encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')
                final_links.append(f"vmess://{new_b64}")
            else:
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # 1. 生成 Base64 订阅并写入 index.html (彻底去掉换行，解决导入出错)
    nodes_text = "\n".join(final_links)
    subscription_b64 = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 2. 生成 Clash 配置
    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]
    cf = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [px['name'] for px in proxies]}
        ]
    }
    cf["proxy-groups"].extend(region_groups)
    cf["rules"] = ["MATCH,🚀 节点选择"]

    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！已通过缓存和增强正则解决‘其它地区’问题。共识别 {len(proxies)} 个节点。")

if __name__ == "__main__":
    main()
