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

# ==================== 工具函数 (保持脚本 A 原型) ====================
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

def get_final_label(server: str, remarks: str = "") -> str:
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

# ==================== 核心解析函数 (兼容 A 的 VMess & B 的 Hy2) ====================
def parse_link(link: str):
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        # --- 脚本 A 的原生 VMess 解析逻辑 (确保不消失) ---
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

        # --- 脚本 B 的 Hy2 修复逻辑 (解决 Hy2 不显示) ---
        elif any(link.startswith(p) for p in ['hysteria2://', 'hy2://', 'hysteria://']):
            u = urllib.parse.urlparse(link)
            orig_remarks = link.split('#', 1)[1] if '#' in link else ""
            return {
                "type": "hysteria2" if "2" in link or "hy2" in link else "hysteria",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username, # 提取密码
                "sni": u.hostname,
                "original_remarks": orig_remarks
            }

        # --- 基础 SS/Trojan/VLESS 解析 ---
        elif link.startswith(('ss://', 'trojan://', 'vless://')):
            u = urllib.parse.urlparse(link)
            orig_remarks = link.split('#', 1)[1] if '#' in link else ""
            return {
                "type": u.scheme,
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username,
                "original_remarks": orig_remarks
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

        # --- 构建 Clash Proxy 字典 ---
        if p["type"] == "vmess":
            d = p["raw_data"]
            proxy_item = {
                "name": new_name,
                "type": "vmess",
                "server": d.get("add"),
                "port": safe_int(d.get("port")),
                "uuid": d.get("id"),
                "alterId": safe_int(d.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1"] else False,
                "network": d.get("net", "tcp"),
                "ws-opts": {"path": d.get("path"), "headers": {"Host": d.get("host", "")}} if d.get("net") == "ws" else None
            }
        elif p["type"] == "hysteria2":
            proxy_item = {
                "name": new_name,
                "type": "hysteria2",
                "server": p["server"],
                "port": p["port"],
                "password": p["password"],
                "sni": p["sni"],
                "skip-cert-verify": True,
                "alpn": ["h3"]
            }
        else:
            # SS / Trojan / VLESS 基础配置
            proxy_item = {
                "name": new_name,
                "type": p["type"],
                "server": p["server"],
                "port": p["port"],
                "password": p.get("password") if p["type"] != "vless" else None,
                "uuid": p.get("password") if p["type"] == "vless" else None,
                "skip-cert-verify": True
            }

        clash_proxies.append(proxy_item)

    # 生成最终 YAML
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [p["name"] for p in clash_proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 全部节点", "type": "select", "proxies": [p["name"] for p in clash_proxies]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"处理完成，生成了 {len(clash_proxies)} 个节点。")

if __name__ == "__main__":
    main()
