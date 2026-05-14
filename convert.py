明白。我将严格遵守你的要求：**仅针对地区识别逻辑进行完善，不改动任何其他代码结构和输出格式。**

为了增强识别率，我在 `get_final_label` 函数中补充了更全面的关键词匹配（涵盖了常见的机场命名习惯），并对 API 请求逻辑做了微调以确保稳定性，其余部分完全保持你提供的原始逻辑。

```python
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

# 增强型图标映射
EMOJI_MAP = {
    "HK": "🇭🇰", "香港": "🇭🇰", "TW": "🇹🇼", "台湾": "🇹🇼", "台灣": "🇹🇼",
    "US": "🇺🇸", "美国": "🇺🇸", "美國": "🇺🇸", "JP": "🇯🇵", "日本": "🇯🇵",
    "SG": "🇸🇬", "新加坡": "🇸🇬", "KR": "🇰🇷", "韩国": "🇰🇷", "韓國": "🇰🇷",
    "GB": "🇬🇧", "英国": "🇬🇧", "UK": "🇬🇧", "DE": "🇩🇪", "德国": "🇩🇪",
    "FR": "🇫🇷", "法国": "🇫🇷", "RU": "🇷🇺", "俄罗斯": "🇷🇺", "CN": "🇨🇳",
    "CA": "🇨🇦", "加拿大": "🇨🇦", "AU": "🇦🇺", "澳大利亚": "🇦🇺", "澳洲": "🇦🇺",
    "NL": "🇳🇱", "荷兰": "🇳🇱", "PH": "🇵🇭", "菲律宾": "🇵🇭", "TH": "🇹🇭", "泰国": "🇹🇭",
    "VN": "🇻🇳", "越南": "🇻🇳", "IN": "🇮🇳", "印度": "🇮🇳", "MY": "🇲🇾", "马来西亚": "🇲🇾",
    "TR": "🇹🇷", "土耳其": "🇹🇷", "BR": "🇧🇷", "巴西": "🇧🇷"
}

def get_final_label(server, remarks):
    """
    完善后的地区识别逻辑
    """
    try:
        if not server: server = ""
        if not remarks: remarks = ""
        search_text = f"{remarks} {server}".lower().strip()
        
        # 扩展识别关键词
        meta = [
            ("香港", r"hk|hong|香港|🇭🇰"), 
            ("台湾", r"tw|taiwan|台湾|台灣|🇹🇼"), 
            ("美国", r"us|united|america|美国|美國|🇺🇸"), 
            ("日本", r"jp|japan|日本|🇯🇵"),
            ("新加坡", r"sg|singapore|新加坡|🇸🇬"), 
            ("韩国", r"kr|korea|韩国|韓國|🇰🇷"),
            ("英国", r"gb|uk|united kingdom|英国|英國|🇬🇧"), 
            ("德国", r"de|germany|德国|🇩🇪"),
            ("俄罗斯", r"ru|russia|俄罗斯|🇷🇺"), 
            ("加拿大", r"ca|canada|加拿大|🇨🇦"), 
            ("泰国", r"th|thailand|泰国|🇹🇭"), 
            ("越南", r"vn|vietnam|越南|🇻🇳"), 
            ("澳大利亚", r"au|australia|澳洲|澳大利亚|🇦🇺"),
            ("法国", r"fr|france|法国|🇫🇷"),
            ("荷兰", r"nl|netherlands|荷兰|🇳🇱"),
            ("菲律宾", r"ph|philippines|菲律宾|🇵🇭"),
            ("印度", r"in|india|印度|🇮🇳"),
            ("巴西", r"br|brazil|巴西|🇧🇷")
        ]
        
        for name, pattern in meta:
            if re.search(pattern, search_text): 
                return f"{EMOJI_MAP.get(name, '🌍')} {name}"
        
        if server in IP_CACHE: return IP_CACHE[server]

        # 清洗 Server 地址
        clean_server = str(server).split(':')[0].split('/')[0].strip()
        # 简单判断是否为可查询地址
        if not clean_server or not re.search(r'[a-zA-Z0-9]', clean_server):
            return "🧿 其它地区"

        time.sleep(0.3) 
        api_url = f"http://ip-api.com/json/{clean_server}?fields=status,country,countryCode&lang=zh-CN"
        resp = requests.get(api_url, timeout=5).json()
        if resp.get("status") == "success":
            code = resp.get("countryCode")
            name_zh = resp.get("country")
            emoji = EMOJI_MAP.get(code) or EMOJI_MAP.get(name_zh, "🌍")
            label = f"{emoji} {name_zh}"
            IP_CACHE[server] = label
            return label
    except:
        pass
    return "🧿 其它地区"

def safe_base64_decode(s):
    try:
        s = urllib.parse.unquote(s)
        s = re.sub(r'[^a-zA-Z0-9+/=]', '', s)
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8', 'ignore').strip()
    except:
        return None

def rebuild_node(link, new_name):
    try:
        if not link or "://" not in link: return None, None, None
        
        if link.startswith('vmess://'):
            content = link[8:].split('#')[0].split('?')[0]
            decoded = safe_base64_decode(content)
            if not decoded: return None, None, None
            
            d = json.loads(decoded)
            addr = d.get("add", "")
            ps = d.get("ps", "")
            label = get_final_label(addr, ps)
            
            std_vmess = {
                "v": "2", "ps": new_name, "add": str(addr),
                "port": str(d.get("port", "443")), "id": str(d.get("id", "")),
                "aid": str(d.get("aid", "0")), "scy": d.get("scy", "auto"),
                "net": d.get("net", "tcp"), "type": d.get("type", "none"),
                "host": d.get("host", ""), "path": d.get("path", ""),
                "tls": d.get("tls", ""), "sni": d.get("sni", ""), "alpn": d.get("alpn", "")
            }
            
            proxy = {
                "name": new_name, "type": "vmess", "server": std_vmess["add"],
                "port": int(std_vmess["port"]) if str(std_vmess["port"]).isdigit() else 443,
                "uuid": std_vmess["id"], "alterId": int(std_vmess["aid"]) if str(std_vmess["aid"]).isdigit() else 0,
                "cipher": "auto", "tls": True if str(std_vmess["tls"]).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": std_vmess["net"]
            }
            if std_vmess["net"] == "ws":
                proxy["ws-opts"] = {"path": std_vmess["path"], "headers": {"Host": std_vmess["host"]}}
            elif std_vmess["net"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": std_vmess["path"]}

            new_json = json.dumps(std_vmess, separators=(',', ':'), ensure_ascii=False)
            new_link = "vmess://" + base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
            return label, proxy, new_link

        else:
            parts = link.split('#', 1)
            base_url = parts[0]
            old_ps = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            host_match = re.search(r'@?([^:/#?]+)', base_url.split('://')[-1])
            host = host_match.group(1) if host_match else ""
            
            label = get_final_label(host, old_ps)
            new_link = f"{base_url}#{urllib.parse.quote(new_name)}"
            proxy = {"name": new_name, "type": "other", "link": new_link}
            return label, proxy, new_link

    except Exception:
        pass
    return None, None, None

def main():
    if not os.path.exists('nodes.txt'):
        return

    try:
        with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
            lines = [l.strip() for l in f if "://" in l]
            raw_links = list(dict.fromkeys(lines)) 
    except Exception:
        return

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

    try:
        content_all = "\n".join(final_links)
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode(content_all.encode('utf-8')).decode('utf-8'))

        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)
    except Exception:
        pass

if __name__ == "__main__":
    main()

```
