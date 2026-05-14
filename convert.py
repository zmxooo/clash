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

# 补全全球主要国家图标映射
EMOJI_MAP = {
    # 亚洲
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "中国": "🇨🇳", "越南": "🇻🇳", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "马来西亚": "🇲🇾", 
    "印度": "🇮🇳", "印尼": "🇮🇩", "土耳其": "🇹🇷", "阿联酋": "🇦🇪", "科威特": "🇰🇼",
    # 美洲
    "美国": "🇺🇸", "加拿大": "🇨🇦", "巴西": "🇧🇷", "阿根廷": "🇦🇷", "墨西哥": "🇲🇽",
    # 欧洲
    "英国": "🇬🇧", "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "荷兰": "🇳🇱", 
    "意大利": "🇮🇹", "西班牙": "🇪🇸", "瑞典": "🇸🇪", "立陶宛": "🇱🇹", "乌克兰": "🇺🇦",
    # 大洋洲及其他
    "澳大利亚": "🇦🇺", "澳洲": "🇦🇺", "新西兰": "🇳🇿", "南非": "🇿🇦"
}

def get_final_label(server, remarks):
    """
    补全全球化识别逻辑：备注关键词 -> IP 库
    """
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    # 补全全球识别正则库
    meta = [
        ("香港", r"hk|hong|香港"), ("台湾", r"tw|taiwan|台湾|台灣"), 
        ("美国", r"us|united states|america|美国|美國"), ("英国", r"gb|uk|united kingdom|英国|英國"), 
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("越南", r"vn|vietnam|越南"), 
        ("科威特", r"kw|kuwait|科威特"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立陶宛"), ("法国", r"fr|france|法国"),
        ("俄罗斯", r"ru|russia|俄罗斯"), ("中国", r"cn|china|中国"),
        ("加拿大", r"ca|canada|加拿大"), ("荷兰", r"nl|netherlands|荷兰"),
        ("菲律宾", r"ph|philippines|菲律宾"), ("泰国", r"th|thailand|泰国"),
        ("澳大利亚", r"au|australia|澳洲|澳大利亚"), ("巴西", r"br|brazil|巴西"),
        ("印度", r"in|india|印度"), ("土耳其", r"tr|turkey|土耳其"),
        ("乌克兰", r"ua|ukraine|乌克兰"), ("阿联酋", r"ae|uae|阿联酋")
    ]
    
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    if server in IP_CACHE: return IP_CACHE[server]

    try:
        time.sleep(0.1) 
        response = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5).json()
        if response.get("status") == "success":
            country = response.get("country")
            label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    return "🧿 其它地区"

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def rebuild_node(link, new_name):
    try:
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded_bytes = base64.b64decode(fix_base64(b64_part))
            d = json.loads(decoded_bytes.decode('utf-8', 'ignore'))
            
            label = get_final_label(d.get("add"), d.get("ps", ""))
            
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(d.get("add", "")).strip(),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")).strip(),
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
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": std_vmess["path"]}

            new_json_str = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_b64 = base64.b64encode(new_json_str.encode('utf-8')).decode('utf-8')
            return label, proxy, f"vmess://{new_b64}"

        elif "://" in link:
            base_url = link.split('#')[0].strip()
            old_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            u = urllib.parse.urlparse(link)
            label = get_final_label(u.hostname, old_remarks)
            proxy = {"name": new_name, "type": "other", "link": link}
            safe_name = urllib.parse.quote(new_name)
            return label, proxy, f"{base_url}#{safe_name}"

    except Exception:
        return None, None, None

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if "://" in line]
        raw_links = list(dict.fromkeys(lines))

    # 预解析以便排序
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
            if proxy and proxy.get("type") != "other":
                clash_proxies.append(proxy)

    # 1. 订阅链接 (Base64)
    content_all = "\n".join(final_links)
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(content_all.encode('utf-8')).decode('utf-8'))

    # 2. Clash 配置
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
