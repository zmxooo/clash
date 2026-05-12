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
        ("🇭🇰 香港", r"hk|香港"), 
        ("🇹🇼 台湾", r"tw|台湾|台灣"),
        ("🇺🇸 美国", r"us|美国|美國"), 
        ("🇬🇧 英国", r"gb|uk|英国|英國"),
        ("🇰🇷 韩国", r"kr|韩国|韓國"), 
        ("🇯🇵 日本", r"jp|日本"),
        ("🇸🇬 新加坡", r"sg|新加坡"), 
        ("🇻🇳 越南", r"vn|越南"),
        ("🇱🇹 立陶宛", r"lt|立陶宛"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): 
            return label
    
    try:
        r = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if r.get("status") == "success":
            c = r.get("country")
            m = {
                "香港": "🇭🇰 香港", "台湾": "🇹🇼 台湾", "美国": "🇺🇸 美国",
                "英国": "🇬🇧 英国", "韩国": "🇰🇷 韩国", "日本": "🇯🇵 日本",
                "新加坡": "🇸🇬 新加坡", "越南": "🇻🇳 越南", "立陶宛": "🇱🇹 立陶宛"
            }
            return m.get(c, f"🌍 {c}")
        # API 限流保护
        time.sleep(1.2)
    except:
        pass
    return "🧿 其它地区"

def parse_link(link):
    try:
        link = link.replace('vmess://vmess://', 'vmess://').strip()
        u = urllib.parse.urlparse(link)
        remarks = u.fragment if u.fragment else ""

        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0].split('?')[0]
            b64 += '=' * (-len(b64) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8'))
            # 统一获取原始备注名
            raw_ps = d.get("ps") or d.get("remarks") or remarks
            return {
                "label": get_final_label(d.get("add"), raw_ps),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port")),
                "uuid": d.get("id"), "alterId": 0, "cipher": "auto",
                "tls": str(d.get("tls","")).lower() in ["tls","true","1"],
                "skip-cert-verify": True, "udp": True
            }

        elif link.startswith(('hysteria2://', 'hy2://', 'hysteria://')):
            return {
                "label": get_final_label(u.hostname, remarks),
                "type": "hysteria2", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username or "", "sni": u.hostname,
                "skip-cert-verify": True, "udp": True
            }

        elif link.startswith('ss://'):
            # 补全 SS 解析
            if '@' in u.netloc:
                userinfo, server_part = u.netloc.split('@', 1)
                if ':' not in userinfo:
                    userinfo += '=' * (-len(userinfo) % 4)
                    userinfo = base64.b64decode(userinfo).decode('utf-8')
                method, password = userinfo.split(':', 1)
            else:
                b64 = u.netloc + '=='
                decoded = base64.b64decode(b64).decode('utf-8')
                method, rest = decoded.split(':', 1)
                password, server_part = rest.rsplit('@', 1)
            host, port = server_part.rsplit(':', 1)
            return {
                "label": get_final_label(host, remarks),
                "type": "ss", "server": host, "port": int(port),
                "cipher": method, "password": password, "udp": True
            }

        elif link.startswith('trojan://'):
            q = urllib.parse.parse_qs(u.query)
            sni = q.get("sni", q.get("host", [u.hostname]))[0] or u.hostname
            return {
                "label": get_final_label(u.hostname, remarks),
                "type": "trojan", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username, "sni": str(sni), "tls": True,
                "skip-cert-verify": True, "udp": True
            }
    except:
        return None

def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        raw_lines = f.read().splitlines()

    # 处理整段 Base64 编码的订阅链接
    ls = []
    for line in raw_lines:
        line = line.strip()
        if not line: continue
        if not any(line.startswith(p) for p in ['vmess://', 'ss://', 'trojan://', 'hy']):
            try:
                line += '=' * (-len(line) % 4)
                decoded = base64.b64decode(line).decode('utf-8')
                ls.extend(decoded.splitlines())
            except:
                ls.append(line)
        else:
            ls.append(line)

    # 方案二：去重逻辑
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
    region_map = defaultdict(list)

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label') # 这里的 label 已经是 "🇭🇰 香港" 这种格式
            idx = len(region_map[label]) + 1
            # --- 核心：在这里彻底统一节点名称格式 ---
            p['name'] = f"{label} {CHANNEL_MARK} {idx:02d}"
            
            proxies.append(p)
            region_map[label].append(p['name'])

    print(f"成功解析: {len(proxies)} 个节点")

    active_regions = list(region_map.keys())
    region_groups = [{"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]} for r in active_regions]

    cf = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]
            },
            {
                "name": "🎬 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "proxies": [px['name'] for px in proxies]
            }
        ]
    }
    cf["proxy-groups"].extend(region_groups)
    cf["rules"] = ["MATCH,🚀 节点选择"]

    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(cf, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
