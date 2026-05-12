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

# 图标映射，不在表里的自动用 🌍
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺"
}

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", r"hk|香港"), ("台湾", r"tw|台湾|台灣"), ("美国", r"us|美国|美國"), 
        ("英国", r"gb|uk|英国|英國"), ("韩国", r"kr|韩国|韓國"), ("日本", r"jp|日本"),
        ("新加坡", r"sg|新加坡"), ("越南", r"vn|越南"), ("立陶宛", r"lt|立陶宛")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    try:
        time.sleep(1.2) # API 频率保护
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            return f"{icon} {country}节点"
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        if link.startswith('vmess://'):
            b64_body = link[8:].split('#')[0]
            b64_body += '=' * (-len(b64_body) % 4)
            raw_data = base64.b64decode(b64_body)
            try:
                decoded_str = raw_data.decode('utf-8')
            except:
                decoded_str = raw_data.decode('gbk')
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
    except:
        return None

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
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # --- 修正导入失败的关键：规范化重新封包 ---
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                # 重新封包必须去掉所有换行符
                new_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')
                final_links.append(f"vmess://{new_b64}")
            else:
                # 处理 SS/Trojan，确保备注被正确 URL 编码
                base_part = l.split('#')[0]
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # --- 修正整体 Base64 订阅字符串的兼容性 ---
    nodes_text = "\n".join(final_links)
    subscription_b64 = base64.b64encode(nodes_text.encode('utf-8')).decode('utf-8').replace('\n', '').replace('\r', '')
    
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # Clash 配置部分
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

    print(f"✅ 处理完成！已修复导入格式错误。")

if __name__ == "__main__":
    main()
