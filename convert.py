import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

# ==================== 配置 ====================
IP_CACHE = {}

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立桃宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷",
}

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    if not isinstance(b64_part, str):
        b64_part = str(b64_part)
    b64_part = re.sub(r'[^a-zA-Z0-9+/=_-]', '', b64_part)
    b64_part = b64_part.replace('-', '+').replace('_', '/')
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except:
        return b""

def safe_int(val, default=443):
    try:
        if isinstance(val, int):
            return val
        clean_val = re.sub(r'\D', '', str(val))
        return int(clean_val) if clean_val else default
    except:
        return default

def get_final_label(server, remarks=""):
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    return "🧿 其他地区"

# ==================== 全协议解析器 (合并修复版) ====================
def parse_link(link):
    try:
        link = link.strip()
        if not link: return None

        # --- 保持 A 脚本 VMess 原有逻辑不动 ---
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            if not raw_data:
                return None
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }

        # --- 参考 B 脚本修复 Hy2 逻辑 ---
        elif any(link.startswith(p) for p in ['hysteria2://', 'hy2://']):
            u = urllib.parse.urlparse(link)
            return {
                "type": "hysteria2",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username,  # Hy2 必须使用 password 字段
                "auth": u.username,      # 同时兼容部分旧版字段
                "sni": u.hostname,
                "skip-cert-verify": True,
                "original_remarks": u.fragment
            }

        # --- 其他协议 (SS/VLESS/Trojan) ---
        elif link.startswith(('ss://', 'trojan://', 'vless://')):
            u = urllib.parse.urlparse(link)
            return {
                "type": u.scheme,
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username if u.scheme != "vless" else None,
                "uuid": u.username if u.scheme == "vless" else None,
                "original_remarks": u.fragment
            }
    except:
        return None
    return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

    seen = set()
    unique_links = []
    for line in lines:
        core = line.split('#')[0]
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    clash_proxies = []
    region_count = defaultdict(int)

    for link in unique_links:
        p = parse_link(link)
        if not p or not p.get("server"):
            continue

        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        region_count[label] += 1
        new_name = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"

        # Clash 节点构建
        if p["type"] == "vmess":
            d = p["raw_data"]
            proxy = {
                "name": new_name,
                "type": "vmess",
                "server": d.get("add"),
                "port": safe_int(d.get("port")),
                "uuid": d.get("id"),
                "alterId": safe_int(d.get("aid", 0)),
                "cipher": "auto",
                "tls": d.get("tls") in ["tls", True, 1],
                "network": d.get("net", "tcp"),
                "ws-opts": {"path": d.get("path"), "headers": {"Host": d.get("host", "")}} if d.get("net") == "ws" else None
            }
        else:
            proxy = {
                "name": new_name,
                "type": p["type"],
                "server": p["server"],
                "port": p["port"],
                "skip-cert-verify": True
            }
            if p.get("password"): proxy["password"] = p["password"]
            if p.get("uuid"): proxy["uuid"] = p["uuid"]
            if p.get("sni"): proxy["sni"] = p["sni"]
            if p["type"] == "hysteria2": proxy["alpn"] = ["h3"]

        clash_proxies.append(proxy)

    # 导出
    config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [p["name"] for p in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 全部节点", "type": "select", "proxies": [p["name"] for p in clash_proxies]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
