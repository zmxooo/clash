import base64, json, yaml, urllib.parse, os, re, requests, time
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://www.gstatic.com/generate_204"

def get_final_label(server, remarks):
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    meta = [
        ("🇭🇰 香港节点", r"hk|香港"), ("🇹🇼 台湾节点", r"tw|台湾|台灣"),
        ("🇺🇸 美国节点", r"us|美国|美國"), ("🇰🇷 韩国节点", r"kr|韩国|韓國"),
        ("🇯🇵 日本节点", r"jp|日本"), ("🇸🇬 新加坡节点", r"sg|新加坡"),
        ("🇩🇪 德国节点", r"de|德国"), ("🇬🇧 英国节点", r"gb|uk|英国|英國"),
        ("🇻🇳 越南节点", r"vn|越南"), ("🇱🇹 立陶宛节点", r"lt|立陶宛")
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    
    try:
        r = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {"美国": "🇺🇸 美国节点", "英国": "🇬🇧 英国节点"}
            return m.get(c, f"🌍 {c}")
    except:
        pass
    return "🧿 其它地区"


# 改进后的去重键（更合理）
def get_dedup_key(p):
    t = p.get('type')
    server = p.get('server')
    port = p.get('port')
    uuid = p.get('uuid') or p.get('password') or ""
    # 关键改动：只通过 server + port + uuid 前16位判断
    return (t, str(server), port, uuid[:16])


def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)

        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port")),
                "uuid": d.get("id"),
                "alterId": 0,
                "cipher": "auto",
                "tls": d.get("tls") in ["tls", True, 1],
                "skip-cert-verify": True,
                "udp": True
            }
        # 其他类型解析保持不变...
        # （为了简洁省略 vless/trojan/ss/hy2，你之前的解析代码可以保留）

    except:
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    node_groups = defaultdict(list)
    for l in ls:
        l = l.strip()
        if not l or any(l.startswith(s) for s in ['import','def','git','#']): continue
        p = parse_link(l)
        if p:
            key = get_dedup_key(p)
            node_groups[key].append((99999, p, l))

    proxies = []
    valid_links = []
    region_map = defaultdict(list)

    print(f"发现 {len(node_groups)} 个唯一节点")

    for key, group in node_groups.items():
        best_p = group[0][1].copy()          # 保留第一个
        label = best_p.pop('label')
        
        idx = len(region_map[label]) + 1
        best_p['name'] = f"{label} {CHANNEL_MARK} {idx:02d}"

        proxies.append(best_p)
        valid_links.append(group[0][2])
        region_map[label].append(best_p['name'])

    print(f"最终生成 {len(proxies)} 个节点 → {', '.join(region_map.keys())}")

    # ==================== 配置生成 ====================
    target_regions = ["🇭🇰 香港节点", "🇹🇼 台湾节点", "🇯🇵 日本节点", "🇸🇬 新加坡节点", "🇰🇷 韩国节点",
                     "🇺🇸 美国节点", "🇩🇪 德国节点", "🇬🇧 英国节点", "🧿 其它地区"]

    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map.get(r, ["Direct"])} for r in target_regions]

    all_nodes = [p['name'] for p in proxies]

    cf = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
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

    print("✅ config.yaml 已生成，请上传覆盖 GitHub 仓库")


if __name__ == "__main__":
    main()
