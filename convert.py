import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港"), 
        ("🇹🇼 台湾节点", r"tw|台湾|台灣"),
        ("🇺🇸 美国节点", r"us|美国|美國"), 
        ("🇬🇧 英国节点", r"gb|uk|英国|英國"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國"), 
        ("🇯🇵 日本节点", r"jp|日本"),
        ("🇸🇬 新加坡节点", r"sg|新加坡"), 
        ("🇻🇳 越南节点", r"vn|越南"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): 
            return label
    
    try:
        # 修正原 URL 拼接缺失 "/" 的语法隐患
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {
                "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点",
                "英国": "🇬🇧 英国节点", "韩国": "🇰🇷 韩国节点", "日本": "🇯🇵 日本节点",
                "新加坡": "🇸🇬 新加坡节点", "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"
            }
            return m.get(c, f"🌍 {c}")
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        
        # --- VMess 逐字符语法校对 ---
        if link.startswith('vmess://'):
            # 1. 提取 Base64：分步切割并取索引 [0]，确保变量始终是字符串类型
            content = link[8:]
            if '#' in content:
                content = content.split('#')[0]
            if '?' in content:
                content = content.split('?')[0]
            
            # 2. 补齐 Base64 填充位
            pad_len = len(content) % 4
            if pad_len != 0:
                content += '=' * (4 - pad_len)
            
            # 3. 解码并转 JSON
            decoded_str = base64.b64decode(content).decode('utf-8')
            d = json.loads(decoded_str)
            
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True
            }

        u = urllib.parse.urlparse(link)

        # --- VLESS 逐字符语法校对 ---
        if link.startswith('vless://'):
            q = urllib.parse.parse_qs(u.query)
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "vless", "server": u.hostname, "port": int(u.port or 443),
                "uuid": u.username, "cipher": "auto", "tls": True,
                "udp": True, "skip-cert-verify": True,
                "network": q.get("type", ["tcp"])[0],
                "servername": q.get("sni", [u.hostname])[0]
            }

        # --- Hysteria2 解析 ---
        elif link.startswith(('hysteria2://', 'hy2://', 'hysteria://')):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "hysteria2", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username or "", "sni": u.hostname,
                "skip-cert-verify": True, "udp": True
            }

        # --- Shadowsocks 解析 ---
        elif link.startswith('ss://'):
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                if len(userinfo) % 4: userinfo += '=' * (4 - len(userinfo) % 4)
                decoded_userinfo = base64.b64decode(userinfo).decode('utf-8')
                method, password = decoded_userinfo.split(':', 1)
            else:
                raw_ss = u.netloc
                if len(raw_ss) % 4: raw_ss += '=' * (4 - len(raw_ss) % 4)
                decoded = base64.b64decode(raw_ss).decode('utf-8')
                method, rest = decoded.split(':', 1)
                password, server_part = rest.rsplit('@', 1)
            host, port = server_part.rsplit(':', 1)
            return {
                "label": get_final_label(host, u.fragment),
                "type": "ss", "server": host, "port": int(port),
                "cipher": method, "password": password, "udp": True
            }

        # --- Trojan 解析 ---
        elif link.startswith('trojan://'):
            q = urllib.parse.parse_qs(u.query)
            sni_list = q.get("sni", q.get("host", [u.hostname]))
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "trojan", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username, "sni": str(sni_list[0]), "tls": True,
                "skip-cert-verify": True, "udp": True
            }
    except:
        return None

def rebuild_link(original_link, new_name):
    try:
        safe_name = urllib.parse.quote(new_name)
        # 获取 # 前面的部分，取 [0] 索引确保获得字符串
        base_part = original_link.split('#')[0]
        return f"{base_part}#{safe_name}"
    except:
        return original_link

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    seen_links = set()
    unique_links = []
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(x) for x in ['import','def','git','#']): 
            continue
        if l not in seen_links:
            seen_links.add(l)
            unique_links.append(l)

    proxies = []
    valid_links = []
    region_map = defaultdict(list)

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            node_name = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            p['name'] = node_name
            proxies.append(p)
            
            # --- 核心修改：统一重构链接用于 Base64 订阅 ---
            valid_links.append(rebuild_link(l, node_name))
            region_map[label].append(node_name)

    print(f"成功解析: {len(proxies)} 个节点")

    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]
    all_nodes = [p['name'] for p in proxies]

    cf = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]},
        "proxies": proxies + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "☢ 负载均衡"] + active_regions + ["Direct"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
            {"name": "☢ 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + active_regions},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择"]},
            {"name": "🤖 AI", "type": "select", "proxies": ["🚀 节点选择"]},
            {"name": "📹 哔哩哔哩", "type": "select", "proxies": ["Direct"]},
            {"name": "🎥 Netflix", "type": "select", "proxies": ["🚀 节点选择"]},
        ] + region_groups,
        "rules": [
            "DOMAIN-SUFFIX,youtube.com,📹 YouTube", "DOMAIN-SUFFIX,googlevideo.com,📹 YouTube",
            "DOMAIN-SUFFIX,telegram.org,📲 Telegram", "DOMAIN-KEYWORD,telegram,📲 Telegram",
            "DOMAIN-KEYWORD,openai,🤖 AI", "DOMAIN-SUFFIX,chatgpt.com,🤖 AI",
            "DOMAIN-SUFFIX,bilibili.com,📹 哔哩哔哩", "DOMAIN-SUFFIX,netflix.com,🎥 Netflix",
            "GEOIP,CN,Direct", "MATCH,🚀 节点选择"
        ]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    with open('index.html', 'w', encoding='utf-8') as f:
        # Base64 编码统一名称后的链接列表
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

    print("🎉 最终同步版发布：VMess/VLESS 找回，订阅名称已完美统一。")

if __name__ == "__main__":
    main()
