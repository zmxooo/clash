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
TEST_URL = "http://gstatic.com"

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
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    return base64.b64decode(b64_part)

def get_final_label(server: str, remarks: str = "") -> str:
    """优先正则识别 → IP自动纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立桃宛", r"lt|lithuania|立桃宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=8)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[server] = label
                return label
        except:
            pass
    return "🧿 其他地区"

def parse_link(link: str):
    """一站式精准解析所有主流协议，直接输出标准 Clash 代理字典"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        # 1. 独立处理 VMess 协议
        if link.lower().startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            server_host = data.get("add")
            raw_ps = data.get("ps", "")
            
            return {
                "label": get_final_label(server_host, raw_ps),
                "type": "vmess",
                "server": server_host,
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": data.get("net", "tcp"),
                "is_vmess_raw": True, # 打上标记方便 main 函数二次编码订阅链接
                "raw_data": data
            }
            
        # 2. 通用解析其他标准 URI 协议 (ss, trojan, vless, hy2)
        elif link.lower().startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            main_part = link.split('#')[0]
            raw_ps = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            proto = main_part.split('://')[0].lower()
            if proto == 'hy2': 
                proto = 'hysteria2'
                
            netloc = main_part.split('://')[1].split('/')[0].split('?')[0]
            auth_str = ""
            if '@' in netloc:
                auth_str = netloc.split('@')[0]
                server_part = netloc.split('@')[1]
            else:
                server_part = netloc
                
            server_host = server_part.split(':')[0]
            port = int(server_part.split(':')[1]) if ':' in server_part else 443
                
            queries = {}
            if '?' in main_part:
                queries = dict(urllib.parse.parse_qsl(main_part.split('?')[1]))
                
            result = {
                "label": get_final_label(server_host, raw_ps),
                "type": proto,
                "server": server_host,
                "port": port
            }

            # Hysteria 2 特征注入
            if proto == "hysteria2":
                result.update({
                    "auth": auth_str,
                    "sni": queries.get("sni", server_host),
                    "skip-cert-verify": True,
                    "up": queries.get("up", "100"),
                    "down": queries.get("down", "100")
                })
                if queries.get("obfs"):
                    result["obfs"] = queries.get("obfs")
                    result["obfs-password"] = queries.get("obfs-password", "")
                    
            # Shadowsocks 特征注入
            elif proto == "ss":
                result['password'] = auth_str.split(':')[1] if ':
