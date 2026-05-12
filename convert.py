import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from urllib.parse import urlparse, parse_qs, unquote

def get_final_label(server: str, remarks: str = "") -> str:
    """IP归属地 + 备注优先匹配"""
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
        if re.search(pattern, text):
            return label

    # IP-API 查询
    try:
        resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country", "")
                mapping = {
                    "中国": "🇨🇳 中国",
                    "香港": "🇭🇰 香港节点",
                    "台湾": "🇹🇼 台湾节点",
                    "美国": "🇺🇸 美国节点",
                    "日本": "🇯🇵 日本节点",
                    "韩国": "🇰🇷 韩国节点",
                    "新加坡": "🇸🇬 新加坡节点",
                    "德国": "🇩🇪 德国节点",
                    "英国": "🇬🇧 英国节点",
                    "越南": "🇻🇳 越南节点",
                    "立陶宛": "🇱🇹 立陶宛节点",
                }
                return mapping.get(country, f"🌍 {country}")
    except:
        pass
    
    return "🧿 其它地区"


def parse_link(link: str):
    """增强型订阅链接解析器"""
    try:
        link = link.strip().replace('vmess://vmess://', 'vmess://')
        if not link:
            return None

        # VMess
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            config = json.loads(base64.b64decode(b64).decode('utf-8'))
            
            return {
                "label": get_final_label(config.get("add"), config.get("ps")),
                "type": "vmess",
                "server": config.get("add"),
                "port": int(config.get("port")),
                "uuid": config.get("id"),
                "alterId": int(config.get("alterId", 0)),
                "cipher": config.get("scy", "auto"),
                "tls": str(config.get("tls", "")).lower() in ["tls", "true", "1"],
                "skip-cert-verify": True,
                "udp": True,
            }

        # VLESS / Trojan
        elif link.startswith(('vless://', 'trojan://')):
            u = urlparse(link)
            q = parse_qs(u.query)
            is_vless = link.startswith('vless://')
            
            sni = q.get("sni", q.get("host", [u.hostname]))[0]
            
            proxy = {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "vless" if is_vless else "trojan",
                "server": u.hostname,
                "port": int(u.port or 443),
                "tls": True,
                "sni": sni,
                "skip-cert-verify": True,
                "udp": True,
            }
            if is_vless:
                proxy["uuid"] = u.username
                proxy["cipher"] = "auto"
            else:
                proxy["password"] = u.username
            return proxy

        # Shadowsocks
        elif link.startswith('ss://'):
            u = urlparse(link)
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                method, password = base64.b64decode(userinfo + '==').decode().split(':', 1)
            else:
                # 老格式
                decoded = base64.b64decode(u.netloc + '==').decode()
                method, rest = decoded.split(':', 1)
                password, server_part = rest.rsplit('@', 1)
            
            host, port = server_part.rsplit(':', 1)
            
            return {
                "label": get_final_label(host, u.fragment),
                "type": "ss",
                "server": host,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True,
            }

        # Hysteria2 / hy2
        elif link.startswith(('hysteria2://', 'hy2://')):
            u = urlparse(link)
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "hysteria2",
                "server": u.hostname,
                "port": int(u.port or 443),
                "password": u.username or "",
                "sni": u.hostname,
                "skip-cert-verify": True,
                "udp": True,
            }

    except Exception as e:
        # print(f"解析失败: {link[:60]}... {e}")
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        links = [line.strip() for line in f if line.strip()]

    proxies = []
    valid_links = []
    region_map = {}
    channel_mark = "@zmxooo"

    print(f"开始解析 {len(links)} 个节点...")

    for link in links:
        if any(link.startswith(x) for x in ['import', 'def', '#', 'http']):
            continue
            
        p = parse_link(link)
        if p:
            valid_links.append(link)
            label = p.pop('label')
            
            # 去重
            if label not in region_map:
                region_map[label] = []
            
            idx = len(region_map[label]) + 1
            p['name'] = f"{label} {channel_mark} {idx:02d}"
            
            proxies.append(p)
            region_map[label].append(p['name'])
            
            time.sleep(0.08)  # 稍微放慢避免 ip-api 限流

    if not proxies:
        print("⚠️ 没有解析到有效节点")
        return

    print(f"✅ 成功解析 {len(proxies)} 个节点")

    # 策略组配置
    target_regions = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", 
                     "🇸🇬 新加坡节点", "🇰🇷 韩国节点", "🇺🇸 美国节点",
                     "🇩🇪 德国节点", "🇬🇧 英国节点", "🧿 其它地区"]

    region_groups = [
        {"name": r, "type": "url-test", "url": "http://www.gstatic.com/generate_204", 
         "interval": 300, "tolerance": 50, "proxies": region_map.get(r, ["Direct"])}
        for r in target_regions
    ]

    all_nodes = [p['name'] for p in proxies]

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "tun": {
            "enable": True,
            "stack": "mixed",
            "auto-route": True,
            "auto-detect-interface": True
        },
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": ["223.5.5.5", "119.29.29.29", "8.8.8.8"]
        },
        "proxies": proxies + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", 
             "proxies": ["⚡ 自动选择", "☢ 负载均衡"] + target_regions + ["Direct"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", 
             "interval": 300, "proxies": all_nodes},
            {"name": "☢ 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", 
             "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": all_nodes},
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + target_regions},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择", "🇸🇬 新加坡节点"]},
            {"name": "🤖 AI", "type": "select", "proxies": ["🇺🇸 美国节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点"]},
            {"name": "📹 哔哩哔哩", "type": "select", "proxies": ["Direct", "🇭🇰 香港节点", "🇹🇼 台湾节点"]},
            {"name": "🎥 Netflix", "type": "select", "proxies": ["🚀 节点选择"]},
        ] + region_groups,
        "rules": [
            "DOMAIN-SUFFIX,youtube.com,📹 YouTube",
            "DOMAIN-SUFFIX,googlevideo.com,📹 YouTube",
            "DOMAIN-SUFFIX,telegram.org,📲 Telegram",
            "DOMAIN-KEYWORD,telegram,📲 Telegram",
            "DOMAIN-KEYWORD,openai,🤖 AI",
            "DOMAIN-SUFFIX,chatgpt.com,🤖 AI",
            "DOMAIN-SUFFIX,bilibili.com,📹 哔哩哔哩",
            "DOMAIN-SUFFIX,netflix.com,🎥 Netflix",
            "GEOIP,CN,Direct",
            "MATCH,🚀 节点选择"
        ]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode('\n'.join(valid_links).encode('utf-8')).decode('utf-8'))

    print("🎉 生成完成！\n   → config.yaml\n   → index.html")


if __name__ == "__main__":
    main()
