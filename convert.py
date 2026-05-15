import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict
import socket   # ← 修复：移动到顶部

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

IP_CACHE = {}

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦",
    "澳大利亚": "🇦🇺", "荷兰": "🇳🇱", "马来西亚": "🇲🇾", "泰国": "🇹🇭", "印度": "🇮🇳",
    "巴西": "🇧🇷", "土耳其": "🇹🇷", "阿联酋": "🇦🇪", "菲律宾": "🇵🇭", "阿根廷": "🇦🇷",
    "新西兰": "🇳🇿", "意大利": "🇮🇹", "西班牙": "🇪🇸", "瑞士": "🇨🇭", "瑞典": "🇸🇪",
    "南非": "🇿🇦", "爱尔兰": "🇮🇪", "墨西哥": "🇲🇽", "乌克兰": "🇺🇦"
}

EMOJI_TO_NAME = {
    "🇭🇰": "香港", "🇹🇼": "台湾", "🇺🇸": "美国", "🇬🇧": "英国", "🇰🇷": "韩国", 
    "🇯🇵": "日本", "🇸🇬": "新加坡", "🇻🇳": "越南", "🇫🇷": "法国", "🇩🇪": "德国",
    "🇷🇺": "俄罗斯", "🇨🇳": "中国", "🇨🇦": "加拿大", "🇦🇺": "澳大利亚", "🇳🇱": "荷兰",
    "🇲🇾": "马来西亚", "🇹🇭": "泰国", "🇮🇳": "印度", "🇧🇷": "巴西", "🇹🇷": "土耳其"
}

def get_final_label(server, remarks):
    """
    企业级现成落地脚本（百级节点精简优化版）
    """
    if not server: 
        return "🌍 其它地区"
        
    text = urllib.parse.unquote(str(remarks)).strip()
    
    # 1. 策略一：纯国旗 Emoji 强截获
    for emoji, name in EMOJI_TO_NAME.items():
        if emoji in text:
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    text_lower = text.lower()
    if CHANNEL_MARK.lower() in text_lower:
        text_lower = text_lower.replace(CHANNEL_MARK.lower(), "")

    # 2. 策略二：常用文本特征与机场三字码正则匹配
    meta = [
        ("香港", r"hk|香港|hong.*kong|hgc|hkbn|hkg"), 
        ("台湾", r"tw|台湾|台灣|taiwan|cht|hinet"), 
        ("美国", r"\bus\b|美国|美國|united.*states|america|lax|sfo|sanjose"), 
        ("英国", r"\buk\b|\bgb\b|英国|英國|united.*kingdom|london|lhr"), 
        ("韩国", r"kr|韩国|韓國|korea|seoul|icn"), 
        ("日本", r"jp|日本|japan|tokyo|osaka|nrt|hnd"),
        ("新加坡", r"\bsg\b|新加坡|singapore|sin"), 
        ("法国", r"\bfr\b|法国|法國|france"),
        ("德国", r"\bde\b|德国|germany|frankfurt|fra")
    ]
    
    matched_country = None
    last_match_pos = -1
    for name, pattern in meta:
        matches = list(re.finditer(pattern, text_lower))
        if matches:
            last_match = matches[-1]
            if last_match.start() > last_match_pos:
                matched_country = name
                last_match_pos = last_match.start()

    if matched_country and matched_country != "中国":
        return f"{EMOJI_MAP.get(matched_country, '🌍')} {matched_country}"

    # 3. 策略三：内存高速缓存判定
    if server in IP_CACHE: 
        return IP_CACHE[server]

    # 4. 策略四：IP 地理位置查询
    clean_server = str(server).split(':')[0] if ':' in str(server) else str(server)
    
    ip_address = clean_server
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_server):
        try:
            ip_address = socket.gethostbyname(clean_server)
        except:
            pass

    # 修复：使用正确的查询接口（原百度接口无效）
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=2.5)
        if response.status_code == 200:
            data = response.json()
            location = data.get("country_name", "") or data.get("country", "")
            for k in EMOJI_MAP.keys():
                if k in location or location in k:
                    label = f"{EMOJI_MAP[k]} {k}"
                    IP_CACHE[server] = label
                    return label
    except:
        pass

    return "🌍 其它地区"


def safe_b64decode(s):
    s = s.strip().replace('_', '/').replace('-', '+')
    padding = len(s) % 4
    if padding: 
        s += "=" * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', 'ignore')
    except:
        return ""


def validate_clash_proxy(proxy):
    """验证节点是否包含 Clash 必需字段"""
    try:
        if not proxy or not isinstance(proxy, dict): 
            return False
        p_type = proxy.get("type")
        if not proxy.get("server") or not proxy.get("port"): 
            return False
        if p_type in ["vmess", "vless", "tuic"]: 
            return bool(proxy.get("uuid"))
        if p_type == "ss": 
            return bool(proxy.get("cipher")) and bool(proxy.get("password"))
        if p_type in ["trojan", "hysteria2"]: 
            return bool(proxy.get("password"))
        return False
    except:
        return False


def parse_link(link):
    """高稳定性全协议无陷阱解析核心"""
    try:
        link = link.strip()
        if not link: 
            return None
        
        node_type = ""
        for proto in ['vless://', 'vmess://', 'ss://', 'trojan://', 'hy2://', 'hysteria2://', 'tuic://']:
            if link.lower().startswith(proto):
                node_type = proto.replace('://', '')
                if node_type == 'hysteria2': 
                    node_type = 'hy2'
                break
        if not node_type: 
            return None

        u = urllib.parse.urlparse(link)
        raw_ps = urllib.parse.unquote(u.fragment) if u.fragment else ""

        # 1. 解析 VMESS
        if node_type == "vmess":
            link_clean = link.replace('vmess://vmess://', 'vmess://')
            b64_part = link_clean[8:].split('#')[0]
            raw_data = safe_b64decode(b64_part)
            d = json.loads(raw_data)
            
            proxy = {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess", "server": d.get("add"), "port": int(d.get("port", 443)),
                "uuid": d.get("id"), "alterId": int(d.get("aid", 0)), "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "skip-cert-verify": True, "network": d.get("net", "tcp"), "raw_json": d 
            }
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", "")}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": d.get("path", "")}
            return proxy

        # 2. 解析 SS
        elif node_type == "ss":
            main_part = link[5:].split('#')[0]
            cipher, password, server, port = "", "", "", 443
            if "@" in main_part:
                userinfo_host = main_part.rsplit('@', 1)
                decoded_userinfo = safe_b64decode(userinfo_host[0])
                if ":" in decoded_userinfo: 
                    cipher, password = decoded_userinfo.split(':', 1)
                server_port = userinfo_host[1]
            else:
                decoded_all = safe_b64decode(main_part)
                if "@" in decoded_all and ":" in decoded_all:
                    userinfo, server_port = decoded_all.rsplit('@', 1)
                    cipher, password = userinfo.split(':', 1)
                else: 
                    return None
            
            if ":" in server_port:
                server, port_part = server_port.split(':', 1)
                port = int(re.sub(r'\D.*', '', port_part))
            else: 
                return None
                
            return {
                "label": get_final_label(server, raw_ps), "type": "ss", 
                "server": server, "port": port, "cipher": cipher, "password": password
            }

        # 3. 解析 通用标准协议（Vless, Trojan, Hy2, Tuic）
        else:
            server = u.hostname
            if not server and "@" in u.netloc: 
                server = u.netloc.split('@')[-1].split(':')[0]
            if not server: 
                return None
            try: 
                port = int(u.port or 443)
            except: 
                port = 443
                
            credential = u.username or u.password or ""
            if not credential and "@" in u.netloc:
                netloc_part = u.netloc.split('@')[0]
                credential = netloc_part.split(':')[-1] if ":" in netloc_part else netloc_part

            proxy = {
                "label": get_final_label(server, raw_ps),
                "type": "ss" if node_type == "ss" else node_type,
                "server": server,
                "port": port
            }
            
            queries = dict(urllib.parse.parse_qsl(u.query))
            sni = queries.get('sni') or queries.get('peer') or server
            
            if node_type == "vless":
                proxy["uuid"] = credential
                proxy["sni"] = sni
                proxy["skip-cert-verify"] = True
                proxy["network"] = queries.get('type', 'tcp')
                if queries.get('security') == 'reality':
                    proxy['reality-opts'] = {'public-key': queries.get('pbk', ''), 'short-id': queries.get('sid', '')}
                if proxy["network"] == "ws":
                    proxy["ws-opts"] = {"path": queries.get('path', '/'), "headers": {"Host": queries.get('host', sni)}}
            elif node_type == "trojan":
                proxy["password"] = credential
                proxy["sni"] = sni
                proxy["skip-cert-verify"] = True
            elif node_type == "hy2":
                proxy["type"] = "hysteria2"
                proxy["password"] = credential
                proxy["sni"] = sni
                proxy["skip-cert-verify"] = True
            elif node_type == "tuic":
                proxy["uuid"] = credential
                proxy["sni"] = sni
                proxy["skip-cert-verify"] = True
            return proxy
    except Exception as e:
        print(f"解析异常已被安全过滤: {str(e)}")
        return None


def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 找不到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        ls = f.read().splitlines()

    unique_links = []
    seen = set()
    for l in ls:
        l = l.strip()
        if l and l not in seen:
            unique_links.append(l)
            seen.add(l)

    print(f"载入去重行数: {len(unique_links)}")

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = [] 

    for l in unique_links:
        p = parse_link(l)
        if p:
            label = p.pop('label')
            idx = len(region_map[label]) + 1
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            
            if p.get('type') == "vmess":
                d = p.pop('raw_json', {})
                if d:
                    d['ps'] = new_name
                    new_json = json.dumps(d, separators=(',', ':')).encode('utf-8')
                    rocket_links.append(f"vmess://{base64.b64encode(new_json).decode('utf-8')}")
            else:
                clean_url = l.split('#')[0]
                rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

            p['name'] = new_name
            if validate_clash_proxy(p):
                clash_proxies.append(p)
                region_map[label].append(new_name)

    # 写入 index.html
    with open('index.html', 'w', encoding='utf-8') as f:
        sub_b64 = base64.b64encode("\n".join(rocket_links).encode('utf-8')).decode('utf-8') if rocket_links else ""
        f.write(sub_b64)
    print(f"index.html 更新完毕，包含 {len(rocket_links)} 节点")

    # 写入 config.yaml
    if clash_proxies:
        active_regions = list(region_map.keys())
        proxy_groups = [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["🎬 自动选择"] + active_regions + ["DIRECT"]},
            {"name": "🎬 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": [px['name'] for px in clash_proxies]}
        ]
        for r in active_regions:
            proxy_groups.append({"name": r, "type": "url-test", "url": TEST_URL, "interval": 300, "proxies": region_map[r]})

        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"mixed-port": 7890, "allow-lan": True, "mode": "rule", "proxies": clash_proxies, "proxy-groups": proxy_groups, "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True, sort_keys=False)
        print("config.yaml 更新成功")
    else:
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"mixed-port": 7890, "mode": "rule", "proxies": [{"name": "DIRECT_NODE", "type": "direct"}], "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}, f)
        print("⚠️ 未发现满足导入条件的 Clash 节点，已启用 DIRECT 兜底写入。")

if __name__ == "__main__":
    main()
