import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# 图标映射表，涵盖常见地区，不在表里的统一用 🌍
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "德国": "🇩🇪", 
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "科威特": "🇰🇼"
}

def get_final_label(server, remarks):
    """
    核心修改：根据 IP 自动识别并生成对应的国家分组名称
    """
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    
    # 1. 依然保留正则匹配以提高效率（常用地区）
    meta = [
        ("香港", r"hk|香港"), ("台湾", r"tw|台湾|台灣"), ("美国", r"us|美国|美國"), 
        ("英国", r"gb|uk|英国|英國"), ("韩国", r"kr|韩国|韓國"), ("日本", r"jp|日本"),
        ("新加坡", r"sg|新加坡"), ("越南", r"vn|越南"), ("立陶宛", r"lt|立陶宛")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    # 2. 正则没中，根据 IP 自动识别全球国家
    try:
        time.sleep(1.1) # 频率限制保护
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            # 动态生成国家分组名称，如 "🌍 科威特节点"
            return f"{icon} {country}节点"
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            # 解决乱码兼容性
            raw_data = base64.b64decode(b64)
            try: decoded_str = raw_data.decode('utf-8')
            except: decoded_str = raw_data.decode('gbk')
            
            d = json.loads(decoded_str)
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True, "raw_json": d 
            }
        elif link.startswith(('ss://', 'trojan://', 'hy')):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "other", "link": link
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
            label = p.pop('label') # 这个 label 现在是自动生成的国家名称
            idx = len(region_map[label]) + 1
            # 严格遵循你的 ID 自动修改名称逻辑
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # 同步修改 Base64 订阅内部名字，确保 index.html 格式统一
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name 
                new_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
                final_links.append(f"vmess://{new_b64}")
            else:
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # 1. 生成 Base64 订阅并写入 index.html
    subscription_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 2. 生成 Clash 配置 (自动生成对应的国家分组)
    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]

    cf = {
        "mixed-port": 7890, "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [p['name'] for p in proxies]}
        ]
    }
    cf["proxy-groups"].extend(region_groups)
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！已根据 IP 识别自动生成全球国家分组，并完成编号。")

if __name__ == "__main__":
    main()
