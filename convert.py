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

def get_final_label(server, remarks):
    # 此处完全保留你原有的正则匹配逻辑
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港"), 
        ("🇹🇼 台湾节点", r"tw|台湾|台灣"),
        ("🇺🇸 美国节点", r"us|美国|美國"), 
        ("🇬🇧 英国节点", r"gb|uk|英国|英國"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國"), 
        ("🇯🇵 日本节点", r"jp|日本"),
        ("🇸🇬 新加坡节点", r"sg|新加坡"), 
        ("🇻🇳 越南节点", r"vn|越南"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): 
            return label
    
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {
                "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点",
                "英国": "🇬🇧 英国节点", "韩国": "🇰🇷 韩国节点", "日本": "🇯🇵 日本节点",
                "新加坡": "🇸🇬 新加坡节点", "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"
            }
            return m.get(c, f"🌍 {c}")
    except: pass
    return "🧿 其它地区"

def parse_link(link):
    # 此处逻辑保持不变，用于解析原始数据
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True,
                "raw_json": d # 临时保存，方便后面重新打包
            }
        elif link.startswith(('ss://', 'trojan://', 'hy')):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "ss" if "ss" in link else "trojan", # 简化处理
                "link": link
            }
    except: return None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    # 方案二去重逻辑
    seen_links = set()
    unique_links = []
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(x) for x in ['import','def','git','#']): continue
        if l not in seen_links:
            seen_links.add(l)
            unique_links.append(l)

    proxies = []
    region_map = defaultdict(list)
    final_links = [] # 用于存放修改名称后的新链接

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            # --- 核心：这里就是你原本通过 id 自动修改名称的逻辑 ---
            new_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            p['name'] = new_name
            
            # --- 为了解决 Base64 订阅不统一，这里同步修改原始链接 ---
            if p['type'] == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name # 强制覆盖内部名称
                new_b64 = base64.b64encode(json.dumps(d).encode('utf-8')).decode('utf-8')
                final_links.append(f"vmess://{new_b64}")
            else:
                # SS/Trojan 等通过修改 fragment (#) 统一名称
                base_link = l.split('#')[0]
                final_links.append(f"{base_link}#{urllib.parse.quote(new_name)}")

            proxies.append(p)
            region_map[label].append(p['name'])

    # 写入 index.html (生成 Base64 订阅)
    subscription_b64 = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(subscription_b64)

    # 写入 Clash 配置 (cf 部分略，逻辑一致)
    print(f"✅ 完成！订阅已通过你的 region_map 逻辑统一名称。")

if __name__ == "__main__":
    main()
