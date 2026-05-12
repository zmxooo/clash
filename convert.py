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

# 图标映射表，不在表里的自动用 🌍
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺"
}

def get_final_label(server, remarks):
    """
    根据 IP 自动识别国家并生成对应的 Label
    """
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    
    # 1. 优先正则匹配常用地区
    meta = [
        ("香港", r"hk|香港"), ("台湾", r"tw|台湾|台灣"), ("美国", r"us|美国|美國"), 
        ("英国", r"gb|uk|英国|英國"), ("韩国", r"kr|韩国|韓國"), ("日本", r"jp|日本"),
        ("新加坡", r"sg|新加坡"), ("越南", r"vn|越南"), ("立陶宛", r"lt|立陶宛")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            icon = EMOJI_MAP.get(name, "🌍")
            return f"{icon} {name}节点"
    
    # 2. 正则没中，强制通过 IP 自动识别全球国家
    try:
        # 保护 API 频率，确保每个 IP 都能查到
        time.sleep(1.2) 
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            country = r.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            # 动态生成分组名，例如 "🇰🇼 科威特节点"
            return f"{icon} {country}节点"
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)

        if link.startswith('vmess://'):
            b64 = link[8:].split('#').split('?')
            b64 += '=' * (-len(b64) % 4)
            
            # 解决乱码兼容性
            raw_data = base64.b64decode(b64)
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
                "skip-cert-verify": True, "udp": True,
                "raw_json": d # 暂存用于重新打包
            }

        elif link.startswith(('ss://', 'trojan://', 'hy')):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "other", "link": link
            }
    except:
        return None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    # 方案二去重逻辑
    unique_links = list(dict.fromkeys([l.strip() for l in ls if l.strip() and not any(l.startswith(x) for x in ['import','def','git','#'])]))

    region_map = defaultdict(list)
    proxies = []
    final_links = [] # 用于 index.html 的 Base64 订阅内容

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label') # 动态获取的国家 Label
            idx = len(region_map[label]) + 1
            
            # 严格遵循你的 ID 自动计数逻辑
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # --- 同步修改链接内部备注，解决 Base64 订阅不统一问题 ---
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name 
                new_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
                final_links.append(f"vmess://{new_b64}")
            else:
                # SS/Trojan 等通过修改 fragment 统一名称
                base_part = l.split('#')
                final_links.append(f"{base_part}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # 1. 生成 Base64 订阅字符串并写入 index.html
    subscription_text = "\n".join(final_links)
    subscription_b64 = base64.b64encode(subscription_text.encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 2. 生成 Clash 配置文件
    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]

    cf = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]
            },
            {
                "name": "🎬 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "proxies": [px['name'] for px in proxies]
            }
        ]
    }
    cf["proxy-groups"].extend(region_groups)
    cf["rules"] = ["MATCH,🚀 节点选择"]

    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

    print(f"✅ 处理完成！已动态识别全球国家分组并统一编号。")

if __name__ == "__main__":
    main()
