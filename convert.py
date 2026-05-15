import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

# --- 配置區 ---
CHANNEL_MARK = "@zmxooo"
IP_CACHE = {}

# 1. 補全全球主要國家圖標映射
EMOJI_MAP = {
    "香港": "🇭🇰", "台灣": "🇹🇼", "日本": "🇯🇵", "韓國": "🇰🇷", "新加坡": "🇸🇬", 
    "中國": "🇨🇳", "越南": "🇻🇳", "泰國": "🇹🇭", "菲律賓": "🇵🇭", "馬來西亞": "🇲🇾", 
    "美國": "🇺🇸", "加拿大": "🇨🇦", "英國": "🇬🇧", "德國": "🇩🇪", "法國": "🇫🇷", 
    "俄羅斯": "🇷🇺", "荷蘭": "🇳🇱", "澳大利亞": "🇦🇺", "土耳其": "🇹🇷", "阿聯酋": "🇦🇪",
    "巴西": "🇧🇷", "阿根廷": "🇦🇷", "義大利": "🇮🇹", "西班牙": "🇪🇸", "瑞典": "🇸🇪"
}

def get_final_label(server, remarks):
    """全球化識別邏輯"""
    try:
        text = urllib.parse.unquote(str(remarks)).lower().strip()
        # 2. 擴展全球國家識別正則
        meta = [
            ("香港", r"hk|hong|香港"), ("台灣", r"tw|taiwan|台灣|台灣"), 
            ("美國", r"us|united states|america|美國|美國"), ("英國", r"gb|uk|united kingdom|英國|英國"), 
            ("韓國", r"kr|korea|韓國|韓國"), ("日本", r"jp|japan|日本"),
            ("新加坡", r"sg|singapore|新加坡"), ("越南", r"vn|vietnam|越南"), 
            ("德國", r"de|germany|德國"), ("俄羅斯", r"ru|russia|俄羅斯"),
            ("荷蘭", r"nl|netherlands|荷蘭"), ("泰國", r"th|thailand|泰國"),
            ("法國", r"fr|france|法國"), ("加拿大", r"ca|canada|加拿大"),
            ("澳大利亞", r"au|australia|澳洲")
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
    return "🧿 其它地區"

def fix_base64(s):
    """保持原有 Base64 補齊邏輯不動"""
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    """
    核心邏輯：1:1 復刻你最初能導入的格式。
    """
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            # 這裡解碼和處理邏輯完全維持你最初的樣子
            decoded = base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore')
            d = json.loads(decoded)
            
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            # 回歸你最初的 VMess 字典結構
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add", "")),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")),
                "aid": str(d.get("aid", "0")), "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""),
                "tls": d.get("tls", ""), "sni": d.get("sni", ""), "alpn": d.get("alpn", "")
            }
            
            # Clash 字典：只保留你原始腳本中有的欄位，確保能導入
            proxy = {
                "name": new_name,
                "type": "vmess",
                "server": std_vmess["add"],
                "port": int(std_vmess["port"]),
                "uuid": std_vmess["id"],
                "alterId": int(std_vmess["aid"]),
                "cipher": "auto",
                "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True,
                "network": std_vmess["net"]
            }
            if std_vmess["net"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}

            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        elif "://" in link:
            # 非 VMess 協議：只改名進 index.html，絕對不進 config.yaml (避免導入報錯)
            base_part = link.split('#')[0]
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            return label, None, f"{base_part}#{urllib.parse.quote(new_name)}"
            
    except: pass
    return None, None, None

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
        
        _, proxy, flink = rebuild_node(item["link"], new_name)
        if flink:
            final_links.append(flink)
            # 重要：只有 VMess 的 proxy 對象不為 None 才會寫入 config.yaml
            # 這樣能保證生成的 config.yaml 格式 100% 正確，不會報 Hysteria2 缺失欄位的錯
            if proxy:
                clash_proxies.append(proxy)

    # 寫入 index.html (維持 Base64 原有邏輯)
    content_all = "\n".join(final_links)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(content_all.encode('utf-8')).decode('utf-8'))

    # 寫入 config.yaml (Clash 導入文件)
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
