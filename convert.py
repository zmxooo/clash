import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"
IP_CACHE = {} 

# 图标映射，不在表里的自动用 🌍
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺"
}

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    
    # 1. 尝试正则匹配（增加对你提供的这些乱码备注的容错，或直接依赖 IP）
    meta = [
        ("香港", r"hk|香港"), ("台湾", r"tw|台湾"), ("美国", r"us|美国"), 
        ("日本", r"jp|日本"), ("德国", r"de|德国|德固") # 针对你给的“德固”
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    # 2. 检查缓存
    if server in IP_CACHE: return IP_CACHE[server]

    # 3. 核心修正：查 IP 拿到任何国家名都直接返回，不再返回“其它地区”
    try:
        time.sleep(1.2) # 保护 API
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}节点"
            IP_CACHE[server] = label
            return label
    except: pass
    
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.strip()
        if link.startswith('vmess://'):
            # 处理填充位
            b64_body = link[8:].split('#')[0]
            b64_body += '=' * (-len(b64_body) % 4)
            # 兼容解码
            raw_data = base64.b64decode(b64_body)
            try: decoded_str = raw_data.decode('utf-8')
            except: decoded_str = raw_data.decode('gbk')
            d = json.loads(decoded_str)
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "aid": int(d.get("aid", 0)),
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "raw_json": d
            }
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = list(dict.fromkeys([l.strip() for l in ls if l.strip() and l.startswith('vmess://')]))
    region_map = defaultdict(list)
    proxies = []
    final_links = []

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            # 同步修改 Base64 订阅内部名字
            d = p.pop('raw_json')
            d['ps'] = new_name
            new_b64 = base64.b64encode(json.dumps(d, separators=(',', ':')).encode('utf-8')).decode('utf-8').replace('\n', '')
            final_links.append(f"vmess://{new_b64}")

            p['name'] = new_name
            proxies.append(p)
            region_map[label].append(new_name)

    # 写入 index.html (Base64 订阅)
    subscription_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8').replace('\n', '')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 写入 Clash 配置文件
    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]
    cf = {
        "proxies": proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
                        {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [px['name'] for px in proxies]}] + region_groups,
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！已识别地区: {', '.join(active_regions)}")

if __name__ == "__main__":
    main()
