import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

CHANNEL_MARK = "@zmxooo"

# ==================== 配置 ====================
IP_CACHE = {}
# 增加地区关键字映射，提升非 API 识别率
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立陶宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "印度": "🇮🇳"
}

# ==================== 工具函数 ====================

def safe_base64_decode(data):
    """安全解码 Base64，处理补齐问题"""
    data = data.replace('-', '+').replace('_', '/')
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    try:
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except:
        return ""

def get_ip_from_host(host):
    """将域名解析为 IP，以便进行地理位置查询"""
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return host
    try:
        return socket.gethostbyname(host)
    except:
        return None

def get_final_label(server: str, remarks: str = "") -> str:
    """识别地理位置：备注优先 -> 域名关键字 -> IP API"""
    text = urllib.parse.unquote(str(remarks)).lower()
    server_lower = server.lower()
    
    # 1. 关键字匹配 (备注 + 域名)
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立陶宛"), ("越南", r"vn|vietnam|越南"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text) or re.search(pattern, server_lower):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # 2. IP API 查询 (增加 DNS 解析)
    ip = get_ip_from_host(server)
    if ip:
        if ip in IP_CACHE: return IP_CACHE[ip]
        try:
            # 免费 API 频率限制，保持 0.4s 间隔
            time.sleep(0.4)
            resp = requests.get(f"http://ip-api.com/json/{ip}?lang=zh-CN", timeout=5)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[ip] = label
                return label
        except: pass
        
    return "🧿 其他地区"

def parse_link(link: str):
    """增强版链接解析，支持 SS/VMess/VLESS/Trojan/Hysteria2"""
    try:
        link = link.strip()
        if not link or any(link.startswith(p) for p in ['#', 'git', 'import']): return None
        
        # 预处理备注
        main_part = link.split('#')[0]
        orig_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""

        # --- VMess ---
        if link.startswith('vmess://'):
            raw_data = safe_base64_decode(main_part[8:])
            if not raw_data: return None
            data = json.loads(raw_data)
            return {
                "type": "vmess", "server": data.get("add"), "port": int(data.get("port", 443)),
                "uuid": data.get("id"), "alterId": 0, "cipher": "auto",
                "tls": data.get("tls") in ["tls", True, 1], "original_remarks": data.get("ps", "")
            }

        # --- Shadowsocks (处理复杂格式) ---
        elif link.startswith('ss://'):
            # 处理 ss://base64(userinfo@host:port) 格式
            inner = main_part[5:]
            if '@' not in inner:
                inner = safe_base64_decode(inner)
            
            user_info, server_info = inner.split('@')
            server, port = server_info.split(':')
            method, password = (user_info if ':' in user_info else safe_base64_decode(user_info)).split(':')
            
            return {
                "type": "ss", "server": server, "port": int(port),
                "cipher": method, "password": password, "original_remarks": orig_remarks
            }

        # --- VLESS / Trojan / Hysteria2 ---
        elif any(link.startswith(p) for p in ['vless://', 'trojan://', 'hysteria2://', 'hy2://']):
            link = link.replace("hy2://", "hysteria2://", 1)
            u = urllib.parse.urlparse(link)
            res = {
                "type": u.scheme, "server": u.hostname, "port": u.port or 443,
                "original_remarks": orig_remarks
            }
            if u.scheme == "hysteria2":
                res.update({"password": u.username, "sni": u.hostname, "skip-cert-verify": True})
            elif u.scheme == "vless":
                res.update({"uuid": u.username, "cipher": "auto", "tls": True, "udp": True})
            elif u.scheme == "trojan":
                res.update({"password": u.username, "sni": u.hostname, "tls": True, "udp": True})
            return res
    except:
        return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        unique_links = list(dict.fromkeys([line.strip() for line in f if line.strip()]))

    print(f"🚀 开始处理 {len(unique_links)} 个节点...")
    
    clash_proxies = []
    final_raw_links = []
    region_count = defaultdict(int)

    for link in unique_links:
        p = parse_link(link)
        if not p or not p.get("server"): continue

        # 核心改进：识别地理位置
        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        region_count[label] += 1
        new_name = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"
        
        # 记录原始链接
        clean_link = link.split('#')[0]
        final_raw_links.append(f"{clean_link}#{urllib.parse.quote(new_name)}")

        # 构建 Clash 对象
        p.pop("original_remarks", None)
        p["name"] = new_name
        clash_proxies.append(p)

    # 1. 生成 Clash YAML
    if clash_proxies:
        groups = [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + list(region_count.keys())},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [px["name"] for px in clash_proxies]}
        ]
        for region in sorted(region_count.keys()):
            groups.append({
                "name": region, "type": "url-test", "proxies": [px["name"] for px in clash_proxies if px["name"].startswith(region)]
            })
        
        config = {"port": 7890, "mode": "rule", "proxies": clash_proxies, "proxy-groups": groups, "rules": ["MATCH,🚀 节点选择"]}
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        print("✅ 已生成 config.yaml")

    # 2. 生成 Base64 订阅
    if final_raw_links:
        b64_content = base64.b64encode("\n".join(final_raw_links).encode('utf-8')).decode('utf-8')
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(b64_content)
        print("✅ 已生成 index.html 订阅文件")

if __name__ == "__main__":
    main()
