import base64
import json
import yaml
import os
import re
import requests
import time
from urllib.parse import urlparse, parse_qs, unquote

def get_final_label(server: str, remarks: str = "") -> str:
    """归属地识别：正则备注优先，API查询次之"""
    text = unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|🇭🇰"),
        ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国节点", r"us|美国|美國|usa|america|🇺🇸"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本节点", r"jp|日本|japan|🇯🇵"),
        ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国节点", r"de|德国|德國|germany|🇩🇪"),
        ("🇬🇧 英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam|🇻🇳"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛|lithuania"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label

    try:
        # 修正：路径必须包含 /json/
        resp = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country", "")
                mapping = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "韩国": "🇰🇷 韩国节点", "新加坡": "🇸🇬 新加坡节点", "德国": "🇩🇪 德国节点", "英国": "🇬🇧 英国节点", "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"}
                return mapping.get(country, f"🌍 {country}")
    except: pass
    return "🧿 其它地区"

def safe_base64_decode(data: str):
    """通用的 Base64 解码保护逻辑"""
    try:
        data = data.replace('-', '+').replace('_', '/') # 兼容 URL Safe 格式
        data += '=' * (-len(data) % 4)
        return base64.b64decode(data).decode('utf-8')
    except: return ""

def parse_link(link: str):
    """核心解析模块"""
    try:
        link = link.strip()
        if not link: return None

        # VMess
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0].split('?')[0]
            config_str = safe_base64_decode(b64_part)
            if not config_str: return None
            config = json.loads(config_str)
            return {
                "label": get_final_label(config.get("add"), config.get("ps")),
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port")),
                "uuid": config.get("id"), "alterId": int(config.get("alterId", 0)),
                "cipher": config.get("scy", "auto"), "tls": str(config.get("tls", "")).lower() in ["tls", "true", "1"],
                "skip-cert-verify": True, "udp": True
            }

        # VLESS / Trojan
        elif link.startswith(('vless://', 'trojan://')):
            u = urlparse(link)
            q = parse_qs(u.query)
            # 严格提取字符串 SNI
            sni_candidate = q.get("sni") or q.get("host") or [u.hostname]
            sni = sni_candidate[0] if sni_candidate else u.hostname
            
            proxy = {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "vless" if link.startswith('vless://') else "trojan",
                "server": u.hostname, "port": int(u.port or 443),
                "tls": True, "sni": sni, "skip-cert-verify": True, "udp": True
            }
            if link.startswith('vless://'): proxy.update({"uuid": u.username, "cipher": "auto"})
            else: proxy["password"] = u.username
            return proxy

        # Shadowsocks
        elif link.startswith('ss://'):
            u = urlparse(link)
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                decoded_info = safe_base64_decode(userinfo)
                if ':' not in decoded_info: return None
                method, password = decoded_info.split(':', 1)
            else:
                decoded_all = safe_base64_decode(u.netloc)
                if '@' not in decoded_all: return None
                method_pass, server_part = decoded_all.rsplit('@', 1)
                method, password = method_pass.split(':', 1)
            
            if ':' in server_part:
                host, port = server_part.rsplit(':', 1)
            else:
                host, port = server_part, 8388
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password, "udp": True}

        # Hysteria2
        elif link.startswith(('hysteria2://', 'hy2://')):
            u = urlparse(link)
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port or 443), "password": u.username or "", "sni": u.hostname, "skip-cert-verify": True, "udp": True}
    except: return None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 找不到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    final_links = []
    headers = {'User-Agent': 'Clash/1.10'} # 模拟Clash头
    for line in raw_lines:
        if line.startswith('http'):
            try:
                print(f"📡 正在拉取订阅: {line[:40]}...")
                resp = requests.get(line, timeout=10, headers=headers)
                if resp.status_code == 200:
                    decoded = safe_base64_decode(resp.text.strip())
                    content = decoded if decoded else resp.text.strip()
                    final_links.extend(content.splitlines())
            except Exception as e: print(f"⚠️ 拉取失败: {e}")
        else:
            final_links.append(line)

    proxies, region_map = [], {}
    channel_mark = "@zmxooo"
    
    print(f"🚀 正在解析 {len(final_links)} 个节点候选...")
    for link in final_links:
        p = parse_link(link)
        if p:
            label = p.pop('label')
            if label not in region_map: region_map[label] = []
            p['name'] = f"{label} {channel_mark} {len(region_map[label]) + 1:02d}"
            proxies.append(p)
            region_map[label].append(p['name'])
            time.sleep(0.05)

    if not proxies:
        print("⚠️ 未发现有效节点")
        return

    target_regions = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点", "🇩🇪 德国节点", "🇬🇧 英国节点", "🧿 其它地区"]
    region_groups = [{"name": r, "type": "url-test", "url": "http://gstatic.com", "interval": 300, "tolerance": 50, "proxies": region_map.get(r, ["Direct"])} for r in target_regions]
    
    all_nodes = [p['name'] for p in proxies]
    config = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info", "ipv6": True,
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]},
        "proxies": proxies + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "☢ 负载均衡"] + target_regions + ["Direct"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": all_nodes},
            {"name": "☢ 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": "http://gstatic.com", "interval": 300, "proxies": all_nodes},
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + target_regions},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择", "🇸🇬 新加坡节点"]},
            {"name": "🤖 AI", "type": "select", "proxies": ["🇺🇸 美国节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点"]},
            {"name": "📹 哔哩哔哩", "type": "select", "proxies": ["Direct", "🇭🇰 香港节点", "🇹🇼 台湾节点"]},
            {"name": "🎥 Netflix", "type": "select", "proxies": ["🚀 节点选择"]},
        ] + region_groups,
        "rules": ["DOMAIN-SUFFIX,google.com,🚀 节点选择", "DOMAIN-SUFFIX,youtube.com,📹 YouTube", "DOMAIN-SUFFIX,netflix.com,🎥 Netflix", "DOMAIN-SUFFIX,telegram.org,📲 Telegram", "DOMAIN-SUFFIX,openai.com,🤖 AI", "DOMAIN-SUFFIX,chatgpt.com,🤖 AI", "DOMAIN-SUFFIX,bilibili.com,📹 哔哩哔哩", "GEOIP,CN,Direct", "MATCH,🚀 节点选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"✨ 搞定！节点总数: {len(proxies)}，配置文件已生成。")

if __name__ == "__main__":
    main()
