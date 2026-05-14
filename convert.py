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

# 缓存 IP 识别结果，避免重复请求
IP_CACHE = {}

# 常用图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

def get_final_label(server, remarks):
    """识别国家并返回精简名称 (例如: 🇩🇪 德国)"""
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    
    # 1. 优先正则匹配 (增加立陶宛等识别)
    meta = [
        ("香港", r"hk|香港|hongkong"), ("台湾", r"tw|台湾|台灣|taiwan"), 
        ("美国", r"us|美国|美國|united states"), ("英国", r"gb|uk|英国|英國"), 
        ("韩国", r"kr|韩国|韓國|korea"), ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore"), ("越南", r"vn|越南|vietnam"), 
        ("科威特", r"kw|科威特|kuwait"), ("德国", r"de|德国|germany"),
        ("立陶宛", r"lt|立陶宛|lithuania")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    # 2. 缓存查询
    if server in IP_CACHE:
        return IP_CACHE[server]

    # 3. IP 自动识别
    try:
        time.sleep(0.5) 
        response = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}" # 💡 已移除“节点平衡”
            IP_CACHE[server] = label
            return label
    except:
        pass
    
    return "🧿 其它地区"

def parse_link(link):
    """解析节点链接并标准化"""
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        if not link: return None
        
        if link.startswith('vmess://'):
            # 处理 Base64 及其填充
            # 🛠️ 预见性精准修复：恢复被错丢的 [0] 索引，使其变回字符串
            b64_part = link[8:].split('#')[0]
            padding = len(b64_part) % 4
            if padding:
                b64_part += "=" * (4 - padding)
            
            raw_data = base64.b64decode(b64_part)
            d = json.loads(raw_data.decode('utf-8', 'ignore'))
            
            proxy = {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port", 443)),
                "uuid": d.get("id"),
                "alterId": int(d.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True,
                "network": d.get("net", "tcp"),
                "raw_json": d 
            }
            
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", "")}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": d.get("path", "")}
            return proxy

        elif link.startswith(('ss://', 'trojan://')):
            u = urllib.parse.urlparse(link)
            raw_ps = urllib.parse.unquote(u.fragment) if u.fragment else ""
            return {
                "label": get_final_label(u.hostname, raw_ps),
                "type": "other", "link": link
            }
    except:
        return None

def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = []
    seen = set()
    for l in ls:
        l = l.strip()
        if l and l not in seen and not any(l.startswith(x) for x in ['import','def','git','#']):
            unique_links.append(l)
            seen.add(l)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = [] 

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            # 💡 精简后的命名格式: 🇩🇪 德国 01 @zmxooo
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            
            # 处理小火箭订阅
            if p.get('type') == "vmess":
                d = p.pop('raw_json')
                d['ps'] = new_name
                new_json = json.dumps(d, separators=(',', ':')).encode('utf-8')
                rocket_links.append(f"vmess://{base64.b64encode(new_json).decode('utf-8')}")
            else:
                # 🛠️ 预见性精准修复：恢复非 Vmess 链接切除尾部备注的 [0] 索引
                clean_url = l.split('#')[0]
                rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

            # 处理 Clash 配置
            p['name'] = new_name
            clash_proxies.append(p)
            region_map[label].append(new_name)

    # 导出文件
    if rocket_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            sub_b64 = base64.b64encode("\n".join(rocket_links).encode('utf-8')).decode('utf-8')
            f.write(sub_b64)

    if clash_proxies:
        active_regions = list(region_map.keys())
        proxy_groups = [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [px['name'] for px in clash_proxies]}
        ]
        for r in active_regions:
            proxy_groups.append({"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]})

        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"mixed-port": 7890, "allow-lan": True, "mode": "rule", "proxies": clash_proxies, "proxy-groups": proxy_groups, "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)

    print("✅ 处理完成！节点名称已精简。")

if __name__ == "__main__":
    main()
