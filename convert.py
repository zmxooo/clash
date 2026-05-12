import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

TEST_URL = "http://www.gstatic.com/generate_204"
CHANNEL_MARK = "@zmxooo"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港|hongkong|🇭🇰"), ("🇹🇼 台湾节点", r"tw|台湾|台灣|taiwan|🇹🇼"),
        ("🇺🇸 美国节点", r"us|美国|美國|america|usa|🇺🇸"), ("🇰🇷 韩国节点", r"kr|韩国|韓國|korea|🇰🇷"),
        ("🇯🇵 日本节点", r"jp|日本|japan|🇯🇵"), ("🇸🇬 新加坡节点", r"sg|新加坡|singapore|🇸🇬"),
        ("🇩🇪 德国节点", r"de|德国|德國|germany|ger|🇩🇪"), ("🇬🇧 英国节点", r"gb|uk|英国|英國|united kingdom|🇬🇧"),
        ("🇻🇳 越南节点", r"vn|越南|vietnam|🇻🇳"), ("🇱🇹 立陶宛节点", r"lt|立陶宛|lithuania")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    try:
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"中国": "🇨🇳 中国", "香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点",
                 "美国": "🇺🇸 美国节点", "日本": "🇯🇵 日本节点", "韩国": "🇰🇷 韩国节点",
                 "新加坡": "🇸🇬 新加坡节点", "德国": "🇩🇪 德国节点", "英国": "🇬🇧 英国节点",
                 "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"}
            return m.get(c, f"🌍 {c}")
    except:
        pass
    return "🧿 其它地区"


def get_dedup_key(p):
    t = p.get('type')
    server = p.get('server')
    port = p.get('port')
    if t in ['vmess', 'vless']:
        return (t, server, port, p.get('uuid'))
    elif t in ['trojan', 'ss', 'hysteria2']:
        return (t, server, port, p.get('password'))
    return (t, server, port)


def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)

        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {"label": get_final_label(d.get("add"), d.get("ps")), "type": "vmess", "server": d.get("add"), "port": int(d.get("port")), "uuid": d.get("id"), "alterId": 0, "cipher": "auto", "tls": d.get("tls") in ["tls", True, 1], "skip-cert-verify": True, "udp": True}

        elif link.startswith(('vless://', 'trojan://')):
            q = urllib.parse.parse_qs(u.query)
            p_type = "vless" if link.startswith('vless://') else "trojan"
            sni = q.get("sni", q.get("host", [u.hostname]))[0] or u.hostname
            p = {"label": get_final_label(u.hostname, u.fragment), "type": p_type, "server": u.hostname, "port": int(u.port or 443), "tls": True, "sni": str(sni), "skip-cert-verify": True, "udp": True}
            if p_type == "vless":
                p.update({"uuid": u.username, "cipher": "auto"})
            else:
                p["password"] = u.username
            return p

        elif link.startswith('ss://'):
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                method, password = base64.b64decode(userinfo + '==').decode('utf-8').split(':', 1)
            else:
                decoded = base64.b64decode(u.netloc + '==').decode('utf-8')
                method, rest = decoded.split(':', 1)
                password, server_part = rest.rsplit('@', 1)
            host, port = server_part.rsplit(':', 1)
            return {"label": get_final_label(host, u.fragment), "type": "ss", "server": host, "port": int(port), "cipher": method, "password": password, "udp": True}

        elif link.startswith(('hysteria2://', 'hy2://')):
            return {"label": get_final_label(u.hostname, u.fragment), "type": "hysteria2", "server": u.hostname, "port": int(u.port or 443), "password": u.username or "", "sni": u.hostname, "skip-cert-verify": True, "udp": True}
    except:
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    print(f"解析 {len(ls)} 行节点...")

    node_groups = defaultdict(list)
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import','def','git','#']): continue
        p = parse_link(l)
        if p:
            key = get_dedup_key(p)
            if key:
                node_groups[key].append((99999, p, l))

    # 去重 + 保留最优（简化版）
    proxies = []
    valid_links = []
    region_map = defaultdict(list)

    for key, group in node_groups.items():
        if len(group) > 1:
            # 简单保留第一个（避免测速问题导致崩溃）
            best_p = group[0][1].copy()
        else:
            best_p = group[0][1].copy()

        label = best_p.pop('label')
        idx = len(region_map[label]) + 1
        best_p['name'] = f"{label} {CHANNEL_MARK} {idx:02d}"

        proxies.append(best_p)
        valid_links.append(group[0][2])
        region_map[label].append(best_p['name'])

    print(f"生成 {len(proxies)} 个节点")

    if not proxies:
        print("没有有效节点")
        return

    # ==================== 生成配置 ====================
    target_regions = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点",
                     "🇺🇸 美国节点", "🇩🇪 德国节点", "🇬🇧 英国节点", "🧿 其它地区"]

    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map.get(r, ["Direct"])} for r in target_regions]

    all_nodes = [p['name'] for p in proxies]

    cf = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29"]},
        "proxies": proxies + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "☢ 负载均衡"] + target_regions + ["Direct"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
            {"name": "☢ 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
            {"name": "📹 YouTube", "type": "select", "proxies": ["🚀 节点选择"] + target_regions},
            {"name": "📲 Telegram", "type": "select", "proxies": ["🚀 节点选择", "🇸🇬 新加坡节点"]},
            {"name": "🤖 AI", "type": "select", "proxies": ["🇺🇸 美国节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点"]},
            {"name": "📹 哔哩哔哩", "type": "select", "proxies": ["Direct", "🇭🇰 香港节点", "🇹🇼 台湾节点"]},
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
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

    print("🎉 生成成功！请重新上传 config.yaml 到 GitHub")


if __name__ == "__main__":
    main()
