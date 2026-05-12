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
    # 1. 检查缓存，避免重复请求
    if server in IP_CACHE: return IP_CACHE[server]

    # 2. 核心修正：优先查 IP 归属地，解决备注名欺骗问题（如备注德国实际是科威特）
    try:
        time.sleep(1.1) # 保护 API 频率
        # 修正：原代码中 ip-api.com{server} 缺少了 /json/ 路径
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}节点"
            IP_CACHE[server] = label
            return label
    except: pass

    # 3. 如果 IP 查询失败，再尝试正则匹配备注名
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", r"hk|香港"), ("台湾", r"tw|台湾"), ("美国", r"us|美国"), 
        ("日本", r"jp|日本"), ("德国", r"de|德国|德固")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.strip()
        u = urllib.parse.urlparse(link)
        
        # 解析 VMess
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
                "uuid": d.get("id"), "aid": int(d.get("aid", 0)),
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "raw_json": d
            }
        
        # 补全：解析 SS/Trojan/Hy2 (解决 index.html 名称不统一)
        elif link.startswith(('ss://', 'trojan://', 'hy')):
            remarks = u.fragment if u.fragment else ""
            return {
                "label": get_final_label(u.hostname, remarks),
                "type": "other", "server": u.hostname, "port": int(u.port or 443),
                "link": link
            }
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    # 支持多协议去重
    unique_links = list(dict.fromkeys([l.strip() for l in ls if l.strip() and any(l.startswith(p) for p in ['vmess://', 'ss://', 'trojan://', 'hy'])]))
    region_map = defaultdict(list)
    proxies = []
    final_links = []

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            # 同步修改 Base64 订阅内容内部备注
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_b64 = base64.b64encode(json.dumps(d, separators=(',', ':')).encode('utf-8')).decode('utf-8').replace('\n', '')
                final_links.append(f"vmess://{new_b64}")
            else:
                # 统一 SS/Trojan 的名称
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            p['name'] = new_name
            proxies.append(p)
            region_map[label].append(new_name)

    # 1. 生成整体 Base64 订阅字符串并写入 index.html
    subscription_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8').replace('\n', '')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 2. 生成 Clash 配置文件
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

    print(f"✅ 修正完成！已根据 IP 强制更正国家。识别地区: {', '.join(active_regions)}")

if __name__ == "__main__":
    main()
