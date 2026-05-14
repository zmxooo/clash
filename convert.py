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

# 补全全球主要国家图标
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "中国": "🇨🇳", "越南": "🇻🇳", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", 
    "美国": "🇺🇸", "加拿大": "🇨🇦", "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", 
    "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺", "土耳其": "🇹🇷", "阿联酋": "🇦🇪",
    "巴西": "🇧🇷", "阿根廷": "🇦🇷", "意大利": "🇮🇹", "西班牙": "🇪🇸"
}

def get_final_label(server, remarks):
    """补全全球识别逻辑，不做逻辑改动"""
    try:
        text = urllib.parse.unquote(str(remarks)).lower().strip()
        # 补全正则库
        meta = [
            ("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台湾|台灣"), 
            ("美国", r"us|united states|america|美国|美國"), ("英国", r"gb|uk|united kingdom|英国|英國"), 
            ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
            ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
            ("俄罗斯", r"ru|russia|俄罗斯"), ("泰国", r"th|thailand|泰国"),
            ("荷兰", r"nl|netherlands|荷兰"), ("法国", r"fr|france|法国"),
            ("加拿大", r"ca|canada|加拿大"), ("澳大利亚", r"au|australia|澳洲")
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
    """
    恢复你最原始的转换逻辑，仅补强地区识别
    """
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            d = json.loads(base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore'))
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            # VMess 必须有 add 和 id 字段
            if not d.get("add") or not d.get("id"): return None, None, None

            proxy = {
                "name": new_name, "type": "vmess", "server": str(d.get("add")),
                "port": int(d.get("port", 443)), "uuid": str(d.get("id")),
                "alterId": int(d.get("aid", 0)), "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": d.get("net", "tcp")
            }
            if d.get("net") == "ws":
                proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
            return label, proxy, link

        elif "://" in link:
            # 对于非 vmess 协议，我们只识别地区，不强行转换成 Clash 对象
            # 除非你明确知道你的原始脚本是如何处理 Hysteria2 的。
            # 这里返回 None 作为 proxy，main 函数中会跳过它进入 config.yaml，但保留在 index.html
            u = urllib.parse.urlparse(link)
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            label = get_final_label(u.hostname, old_remarks)
            return label, None, link
    except: pass
    return None, None, None

def main():
    if not os.path.exists('nodes.txt'): return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        raw_links = list(dict.fromkeys([line.strip() for line in f if "://" in line]))

    parsed_items = []
    for link in raw_links:
        # 第一次解析，获取 Label 用于排序
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
        
        _, proxy, original_link = rebuild_node(item["link"], new_name)
        
        # 构造重命名后的链接给 index.html
        base_link = original_link.split('#')[0]
        final_flink = f"{base_link}#{urllib.parse.quote(new_name)}"
        final_links.append(final_flink)
        
        # 只有真正合规的 proxy 才进入 config.yaml
        if proxy and isinstance(proxy, dict) and proxy.get("server"):
            clash_proxies.append(proxy)

    # 1. 订阅链接 (Base64) - 这个始终会更新
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # 2. Clash 配置 - 只有 VMess 且字段完整的才会进入
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
