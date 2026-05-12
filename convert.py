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
TEST_URL = "http://www.gstatic.com/generate_204"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港"), ("🇹🇼 台湾节点", r"tw|台湾|台灣"),
        ("🇺🇸 美国节点", r"us|美国|美國"), ("🇬🇧 英国节点", r"gb|uk|英国|英國"),
        ("🇰🇷 韩国节点", r"kr|韩国|韓國"), ("🇯🇵 日本节点", r"jp|日本"),
        ("🇸🇬 新加坡节点", r"sg|新加坡"), ("🇻🇳 越南节点", r"vn|越南"),
        ("🇱🇹 立陶宛节点", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    try:
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"香港": "🇭🇰 香港节点", "台湾": "🇹🇼 台湾节点", "美国": "🇺🇸 美国节点",
                 "英国": "🇬🇧 英国节点", "韩国": "🇰🇷 韩国节点", "日本": "🇯🇵 日本节点",
                 "新加坡": "🇸🇬 新加坡节点", "越南": "🇻🇳 越南节点", "立陶宛": "🇱🇹 立陶宛节点"}
            return m.get(c, f"🌍 {c}")
    except:
        pass
    return "🧿 其它地区"


def parse_link(link):
    try:
        original_link = link
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)

        # VMess
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True
            }

        # Hysteria2 / hy2 / hysteria
        elif any(link.startswith(p) for p in ['hysteria2://', 'hy2://', 'hysteria://']):
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "hysteria2", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username or "", "sni": u.hostname,
                "skip-cert-verify": True, "udp": True
            }

        # SS
        elif link.startswith('ss://'):
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                try:
                    method, password = base64.b64decode(userinfo + '==').decode('utf-8').split(':', 1)
                except:
                    method, password = "aes-256-gcm", userinfo
            else:
                decoded = base64.b64decode(u.netloc + '==').decode('utf-8')
                method, rest = decoded.split(':', 1)
                password, server_part = rest.rsplit('@', 1)
            host, port = server_part.rsplit(':', 1)
            return {
                "label": get_final_label(host, u.fragment),
                "type": "ss", "server": host, "port": int(port),
                "cipher": method, "password": password, "udp": True
            }

        # Trojan
        elif link.startswith('trojan://'):
            q = urllib.parse.parse_qs(u.query)
            sni = q.get("sni", q.get("host", [u.hostname]))[0] or u.hostname
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "trojan", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username, "sni": str(sni), "tls": True,
                "skip-cert-verify": True, "udp": True
            }

    except Exception as e:
        # print(f"解析失败: {link[:60]}...")   # 调试时可取消注释
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    # 只去除完全相同的字符串
    seen = set()
    unique_links = [l.strip() for l in ls if l.strip() and not any(l.strip().startswith(x) for x in ['import','def','git','#']) and l.strip() not in seen and not seen.add(l.strip())]

    print(f"原始行数: {len(ls)}")
    print(f"去重后链接数: {len(unique_links)}")

    proxies = []
    valid_links = []
    region_map = defaultdict(list)
    failed = 0

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            p['name'] = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            proxies.append(p)
            valid_links.append(l)
            region_map[label].append(p['name'])
        else:
            failed += 1

    print(f"成功解析: {len(proxies)} 个节点")
    print(f"解析失败: {failed} 个")
    print(f"地区分布: {dict((k, len(v)) for k,v in region_map.items())}")

    # ==================== 生成配置 ====================
    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]

    all_nodes = [p['name'] for p in proxies]

    cf = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
        "tun": {"enable": True, "stack": "mixed", "auto-route": True, "auto-detect-interface": True},
        "dns": {"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["223.5.5.5", "119.29.29.29"]},
        "proxies": proxies + [{"name": "Direct", "type": "direct"}],
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "☢ 负载均衡"] + active_regions + ["Direct"]},
            {"name": "⚡ 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
            {"name": "☢ 负载均衡", "type": "load-balance", "strategy": "consistent-hashing", "url": TEST_URL, "interval": 300, "proxies": all_nodes},
        ] + [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions],
        "rules": ["GEOIP,CN,Direct", "MATCH,🚀 节点选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(valid_links).encode('utf-8')).decode('utf-8'))

    print("🎉 生成完成！")


if __name__ == "__main__":
    main()
