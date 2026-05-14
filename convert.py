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

# 全球国家图标库
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "中国": "🇨🇳", "越南": "🇻🇳", "泰国": "🇹🇭", "美国": "🇺🇸", "加拿大": "🇨🇦", 
    "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", 
    "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", "印度": "🇮🇳", "土耳其": "🇹🇷", "阿联酋": "🇦🇪",
    "澳大利亚": "🇦🇺", "巴西": "🇧🇷", "阿根廷": "🇦🇷", "新西兰": "🇳🇿", "意大利": "🇮🇹"
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
        # --- VMess 逻辑 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            d = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            proxy = {
                "name": new_name, "type": "vmess", "server": str(d.get("add", "")).strip(),
                "port": int(d.get("port", 443)), "uuid": str(d.get("id", "")),
                "alterId": int(d.get("aid", 0)), "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": d.get("net", "tcp")
            }
            if d.get("net") == "ws":
                proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
            return label, proxy, link # 返回原始 link 保证 index.html 不变

        # --- Hysteria2 / VLESS / SS / Trojan 逻辑 ---
        elif "://" in link:
            u = urllib.parse.urlparse(link)
            protocol = u.scheme
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            label = get_final_label(u.hostname, old_remarks)
            
            # 基础对象
            proxy = {
                "name": new_name,
                "server": u.hostname,
                "port": u.port if u.port else 443,
                "udp": True
            }

            # 针对不同协议补全字段
            if protocol == "shadowsocks" or protocol == "ss":
                proxy["type"] = "ss"
                # 注意：SS 需要密码和加密方式，这里假设原链接包含用户信息
                if u.username:
                    user_info = base64.b64decode(fix_base64(u.username)).decode().split(':')
                    proxy["cipher"], proxy["password"] = user_info[0], user_info[1]
            
            elif protocol == "hysteria2" or protocol == "hy2":
                proxy["type"] = "hysteria2"
                proxy["password"] = u.username
                # 修复报错：补全强制要求的 up 和 down 字段
                proxy["up"] = 15 
                proxy["down"] = 50
                proxy["skip-cert-verify"] = True

            elif protocol == "vless":
                proxy["type"] = "vless"
                proxy["uuid"] = u.username
                proxy["tls"] = True
                proxy["skip-cert-verify"] = True

            return label, proxy, link

    except: pass
    return "🧿 其它地区", None, None

def main():
    if not os.path.exists('nodes.txt'): return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        raw_links = list(dict.fromkeys([line.strip() for line in f if "://" in line]))

    parsed_items = []
    for link in raw_links:
        label, _, _ = rebuild_node(link, "TEMP")
        if label:
            parsed_items.append({"label": label, "link": link})

    parsed_items.sort(key=lambda x: x["label"])

    final_links = []
    clash_proxies = []
    counters = defaultdict(int)

    for item in parsed_items:
        label = item["label"]
        counters[label] += 1
        new_name = f"{label} {counters[label]:02d} | {CHANNEL_MARK}"
        
        _, proxy, _ = rebuild_node(item["link"], new_name)
        # 构造 index.html 使用的重命名链接
        base_link = item["link"].split('#')[0]
        final_flink = f"{base_link}#{urllib.parse.quote(new_name)}"
        
        final_links.append(final_flink)
        if proxy:
            clash_proxies.append(proxy)

    # 1. 订阅链接 (Base64)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # 2. Clash 配置
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
