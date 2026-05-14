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
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立陶宛": "🇱🇹",
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

def safe_split(text: str, sep: str, default_val: str = "auto"):
    if not text:
        return [default_val, ""]
    if sep in text:
        parts = text.split(sep, 1)
        return parts if len(parts) == 2 else [parts, ""]
    return [str(text), ""]

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
        ("立陶宛", r"lt|lithuania|立桃宛|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=5)
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
    """【工业级重构】针对特殊参数符号与特殊字符导致的 URL 错位进行预清洗"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        orig_remarks = ""
        if '#' in link:
            parts = link.split('#', 1)
            clean_link_str = parts[0]
            orig_remarks = parts[1]
        else:
            clean_link_str = link

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
            
        elif link.startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            is_hy2_raw = clean_link_str.startswith("hy2://")
            
            # 【核心修复】防止 sni 中带有的 %2F%2F (//) 污染 urlparse 的 host 解析
            safe_uri = clean_link_str
            if "sni=" in safe_uri:
                # 临时替换 sni 中的敏感符号，防止 urlparse 误判路径
                safe_uri = safe_uri.replace("%2F", "_ESC_SLASH_").replace("%2f", "_ESC_SLASH_")

            if is_hy2_raw:
                parse_uri = "hysteria2://" + safe_uri[6:]
            else:
                parse_uri = safe_uri
                
            u = urllib.parse.urlparse(parse_uri)
            
            # 还原提取出的 hostname 和 query 字段
            hostname = u.hostname.replace("_ESC_SLASH_", "/") if u.hostname else ""
            query_str = u.query.replace("_ESC_SLASH_", "%2F")

            return {
                "type": "hysteria2" if u.scheme in ["hy2", "hysteria2"] else u.scheme,
                "is_hy2_raw": is_hy2_raw,
                "link_str_no_hash": clean_link_str, 
                "url_obj": u,
                "query_str": query_str,
                "server": hostname,
                "original_remarks": orig_remarks
            }
    except Exception as e:
        return None
    return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [lin
