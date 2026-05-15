import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

# --- 配置区 ---
CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"
IP_CACHE = {}

# 常用图标映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "法国": "🇫🇷"
}

def get_final_label(server, remarks):
    """识别国家：正则匹配备注 + IP 库查询"""
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("香港", r"hk|香港|hongkong"), ("台湾", r"tw|台湾|台灣|taiwan"), 
        ("美国", r"us|美国|美國|united states"), ("英国", r"gb|uk|英国|英國"), 
        ("韩国", r"kr|韩国|韓國|korea"), ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore"), ("德国", r"de|德国|germany")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    if server in IP_CACHE: return IP_CACHE[server]
    try:
        time.sleep(0.2) 
        response = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except: pass
    return "🧿 其它地区"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split())
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """深度解析并重构不同协议的节点数据"""
    try:
        # --- VMess 协议 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            d = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
            label = get_final_label(d.get("add"), d.get("ps", ""))
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add")).strip(),
                "port": str(d.get("port")), "id": str(d.get("id")), "aid": str(d.get("aid", "0")),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""), "tls": d.get("tls", "")
            }
            proxy = {
                "name": new_name, "type": "vmess", "server": std_vmess["add"],
                "port": int(std_vmess["port"]), "uuid": std_vmess["id"], "alterId": int(std_vmess["aid"]),
                "cipher": "auto", "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "network": std_vmess["net"], "skip-cert-verify": True
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": std_vmess["path"]}
            
            new_b64 = base64.b64encode(json.dumps(std_vmess).encode()).decode()
            return label, proxy, f"vmess://{new_b64}"

        # --- 通用协议 (SS, Trojan, VLESS, HY2) ---
        u = urllib.parse.urlparse(link)
        scheme = u.scheme.lower()
        old_remarks = urllib.parse.unquote(u.fragment) if u.fragment else ""
        label = get_final_label(u.hostname, old_remarks)
        
        proxy = {"name": new_name, "server": u.hostname, "port": u.port, "skip-cert-verify": True}

        if scheme == "ss":
            user_info = u.username if u.username else base64.b64decode(fix_base64(u.netloc.split('@')[0])).decode()
            method, password = user_info.split(':') if ':' in user_info else ("aes-256-gcm", user_info)
            proxy.update({"type": "ss", "cipher": method, "password": password})
        elif scheme == "trojan":
            proxy.update({"type": "trojan", "password": u.username, "sni": u.hostname})
        elif scheme == "vless":
            params = dict(urllib.parse.parse_qsl(u.query))
            proxy.update({
                "type": "vless", "uuid": u.username, "cipher": "auto",
                "tls": True if params.get("security") in ["tls", "reality"] else False,
                "network": params.get("type", "tcp"), "sni": params.get("sni", params.get("host", ""))
            })
        elif scheme in ["hysteria2", "hy2"]:
            proxy.update({"type": "hysteria2", "password": u.username, "sni": u.hostname})
        else: return None, None, None

        return label, proxy, f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}"
    except: return None, None, None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    region_map = defaultdict(list)
    clash_proxies, rocket_links = [], []

    for l in raw_links:
        # 预扫获取国家分组
        lbl, _, _ = rebuild_node(l, "TEMP")
        if not lbl: continue
        
        new_name = f"{lbl} {len(region_map[lbl])+1:02d} {CHANNEL_MARK}"
        label, proxy, r_link = rebuild_node(l, new_name)
        if proxy and r_link:
            region_map[label].append(new_name)
            clash_proxies.append(proxy)
            rocket_links.append(r_link)

    # 导出 index.html (小火箭 Base64 订阅)
    if rocket_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(rocket_links).encode()).decode())

    # 导出 clash_config.yaml (Clash 配置文件)
    if clash_proxies:
        active_regions = sorted(list(region_map.keys()))
        groups = [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [p['name'] for p in clash_proxies]}
        ]
        for r in active_regions:
            groups.append({"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]})

        config = {
            "mixed-port": 7890, "allow-lan": True, "mode": "rule", 
            "proxies": clash_proxies, "proxy-groups": groups, "rules": ["MATCH,🚀 节点选择"]
        }
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
