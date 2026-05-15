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
IP_CACHE = {}

# 图标映射库
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "中国": "🇨🇳", "越南": "🇻🇳", "泰国": "🇹🇭", "美国": "🇺🇸", "加拿大": "🇨🇦", 
    "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", 
    "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", "澳大利亚": "🇦🇺", "巴西": "🇧🇷"
}

def get_final_label(server, remarks):
    try:
        text = urllib.parse.unquote(str(remarks)).lower().strip()
        meta = [
            ("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台湾|台灣"), 
            ("美国", r"us|united states|america|美国|美國"), ("英国", r"gb|uk|united kingdom|英国|英國"), 
            ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
            ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
            ("俄罗斯", r"ru|russia|俄罗斯"), ("泰国", r"th|thailand|泰国")
        ]
        for name, pattern in meta:
            if re.search(pattern, text): 
                return f"{EMOJI_MAP.get(name, '🌍')} {name}"
        if server in IP_CACHE: return IP_CACHE[server]
        time.sleep(0.1) 
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
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded = base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore')
            d = json.loads(decoded)
            label = get_final_label(d.get("add"), d.get("ps", ""))
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add")),
                "port": str(d.get("port", "443")), "id": str(d.get("id")),
                "aid": str(d.get("aid", "0")), "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""),
                "tls": d.get("tls", ""), "sni": d.get("sni", ""), "alpn": d.get("alpn", "")
            }
            proxy = {
                "name": new_name, "type": "vmess", "server": std_vmess["add"],
                "port": int(std_vmess["port"]), "uuid": std_vmess["id"],
                "alterId": int(std_vmess["aid"]), "cipher": "auto",
                "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": std_vmess["net"]
            }
            if std_vmess["net"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            return label, proxy, f"vmess://{base64.b64encode(json.dumps(std_vmess, ensure_ascii=False).encode('utf-8')).decode('utf-8')}"
        elif "://" in link:
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            return label, None, f"{base_url}#{urllib.parse.quote(new_name)}"
    except: pass
    return None, None, None

def main():
    if not os.path.exists('nodes.txt'): return
    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        raw_links = list(dict.fromkeys([line.strip() for line in f if "://" in line]))

    parsed_items = []
    for link in raw_links:
        label, _, _ = rebuild_node(link, "TEMP")
        if label: parsed_items.append({"label": label, "link": link})
    
    parsed_items.sort(key=lambda x: x["label"])
    final_links, clash_proxies, counters = [], [], defaultdict(int)

    for item in parsed_items:
        label = item["label"]
        counters[label] += 1
        new_name = f"{label} {counters[label]:02d} | {CHANNEL_MARK}"
        _, proxy, flink = rebuild_node(item["link"], new_name)
        if flink:
            final_links.append(flink)
            if proxy: clash_proxies.append(proxy)

    # 写入 index.html (保持 Base64 逻辑)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # --- 重点修复：为 config.yaml 补全策略组 ---
    proxy_names = [p["name"] for p in clash_proxies]
    config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "DIRECT"] + proxy_names
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": proxy_names
            }
        ],
        "rules": ["MATCH,🚀 节点选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
