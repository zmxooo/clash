import base64
import json
import yaml
import urllib.parse
import re
import os
import requests
from collections import defaultdict

# ==================== 配置区 ====================
CONFIG = {
    "channel_mark": "@zmxooo",
    "input_file": "nodes.txt",
    "output_yaml": "config.yaml",
    "output_base64": "subscribe.txt"
}

# ==================== 工具函数 ====================
def safe_decode_b64(text):
    """极致兼容的 Base64 解码"""
    try:
        # 剔除可能存在的协议头、备注和无效字符
        text = text.split('#')[0].split('?')[0].strip()
        text = re.sub(r'[^a-zA-Z0-9+/=_-]', '', text)
        text = text.replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding:
            text += "=" * (4 - padding)
        return base64.b64decode(text).decode('utf-8', 'ignore')
    except:
        return ""

def get_region_emoji(remarks, server=""):
    """基于备注的高精匹配"""
    text = urllib.parse.unquote(str(remarks)).lower()
    mapping = [
        ("🇭🇰 香港", r"hk|hongkong|香港"),
        ("🇹🇼 台湾", r"tw|taiwan|台|新北"),
        ("🇺🇸 美国", r"us|united|america|美国"),
        ("🇯🇵 日本", r"jp|japan|日本"),
        ("🇸🇬 新加坡", r"sg|singapore|新加"),
        ("🇰🇷 韩国", r"kr|korea|韩国"),
        ("🇬🇧 英国", r"gb|uk|united kingdom|英国"),
        ("🇩🇪 德国", r"de|germany|德国"),
        ("🇷🇺 俄罗斯", r"ru|russia|俄罗斯")
    ]
    for label, pattern in mapping:
        if re.search(pattern, text):
            return label
    return "🌍 其他地区"

# ==================== 核心解析器 ====================
def parse_node(link):
    link = link.strip()
    if not link: return None
    
    try:
        # --- VMess ---
        if link.startswith('vmess://'):
            raw = safe_decode_b64(link[8:])
            if not raw: return None
            data = json.loads(raw)
            return {
                "type": "vmess",
                "label": get_region_emoji(data.get("ps"), data.get("add")),
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": data.get("tls") in ["tls", True, 1, "1"],
                "network": data.get("net", "tcp"),
                "ws-opts": {"path": data.get("path"), "headers": {"Host": data.get("host", "")}} if data.get("net") == "ws" else None,
                "orig_link": link
            }

        # --- Hysteria 2 / Hy2 ---
        elif link.startswith(('hy2://', 'hysteria2://')):
            u = urllib.parse.urlparse(link)
            return {
                "type": "hysteria2",
                "label": get_region_emoji(u.fragment, u.hostname),
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username,
                "sni": u.hostname,
                "skip-cert-verify": True,
                "alpn": ["h3"],
                "orig_link": link
            }

        # --- Shadowsocks / Trojan / VLESS ---
        elif link.startswith(('ss://', 'trojan://', 'vless://')):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)
            p_type = u.scheme
            node = {
                "type": p_type,
                "label": get_region_emoji(u.fragment, u.hostname),
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username if p_type != "vless" else None,
                "uuid": u.username if p_type == "vless" else None,
                "sni": q.get("sni", [u.hostname])[0],
                "tls": True,
                "skip-cert-verify": True,
                "orig_link": link
            }
            if p_type == "ss": node["cipher"] = "auto"
            return node
    except:
        return None

# ==================== 执行与输出 ====================
def main():
    if not os.path.exists(CONFIG["input_file"]):
        print(f"找不到 {CONFIG['input_file']}")
        return

    with open(CONFIG["input_file"], 'r', encoding='utf-8') as f:
        raw_links = f.read().splitlines()

    proxies = []
    region_counter = defaultdict(int)

    for link in raw_links:
        node = parse_node(link)
        if node:
            label = node.pop("label")
            region_counter[label] += 1
            node["name"] = f"{label} {region_counter[label]:02d} {CONFIG['channel_mark']}"
            proxies.append(node)

    if not proxies:
        print("未识别到有效节点。")
        return

    # 1. 生成 Clash YAML
    clash_config = {
        "proxies": [p for p in proxies],
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [p["name"] for p in proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 全部节点", "type": "select", "proxies": [p["name"] for p in proxies]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }
    
    with open(CONFIG["output_yaml"], 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    # 2. 生成通用 Base64 订阅内容
    raw_sub_text = "\n".join([p.get("orig_link", "") for p in proxies])
    b64_sub_text = base64.b64encode(raw_sub_text.encode()).decode()
    with open(CONFIG["output_base64"], 'w', encoding='utf-8') as f:
        f.write(b64_sub_text)

    print(f"✅ 转换完成！共计 {len(proxies)} 个节点。")
    print(f"YAML 订阅: {CONFIG['output_yaml']}")
    print(f"Base64 订阅: {CONFIG['output_base64']}")

if __name__ == "__main__":
    main()
