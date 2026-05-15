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

IP_CACHE = {}

# 扩展后的国家与 Emoji 映射表
EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷", 
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "立陶宛": "🇱🇹", "科威特": "🇰🇼",
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦",
    "澳大利亚": "🇦🇺", "荷兰": "🇳🇱", "马来西亚": "🇲🇾", "泰国": "🇹🇭", "印度": "🇮🇳",
    "巴西": "🇧🇷", "土耳其": "🇹🇷", "阿联酋": "🇦🇪", "菲律宾": "🇵🇭", "阿根廷": "🇦🇷",
    "新西兰": "🇳🇿", "意大利": "🇮🇹", "西班牙": "🇪🇸", "瑞士": "🇨🇭", "瑞典": "🇸🇪",
    "南非": "🇿🇦", "爱尔兰": "🇮🇪", "墨西哥": "🇲🇽", "乌克兰": "🇺🇦"
}

def get_final_label(server, remarks):
    if not server: 
        return "🌍 其它地区"
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    # 扩展后的正则匹配规则段
    meta = [
        ("香港", r"hk|香港|hongkong"), ("台湾", r"tw|台湾|台灣|taiwan"), 
        ("美国", r"us|美国|美國|united states"), ("英国", r"gb|uk|英国|英國"), 
        ("韩国", r"kr|韩国|韓國|korea"), ("日本", r"jp|日本|japan"),
        ("新加坡", r"sg|新加坡|singapore"), ("越南", r"vn|越南|vietnam"), 
        ("科威特", r"kw|科威特|kuwait"), ("德国", r"de|德国|germany"),
        ("立陶宛", r"lt|立陶宛|lithuania"),
        ("澳大利亚", r"au|australia|澳洲|澳大利亚"), ("荷兰", r"nl|netherlands|holland|荷兰"),
        ("马来西亚", r"my|malaysia|马来西亚|大马"), ("泰国", r"th|thailand|泰国"),
        ("印度", r"in|india|印度"), ("巴西", r"br|brazil|巴西"),
        ("土耳其", r"tr|turkey|土耳其"), ("阿联酋", r"ae|uae|阿联酋|迪拜"),
        ("菲律宾", r"ph|philippines|菲律宾"), ("阿根廷", r"ar|argentina|阿根廷"),
        ("新西兰", r"nz|new zealand|新西兰"), ("意大利", r"it|italy|意大利"),
        ("西班牙", r"es|spain|西班牙"), ("瑞士", r"ch|switzerland|瑞士"),
        ("瑞典", r"se|sweden|瑞典"), ("南非", r"za|south africa|南非"),
        ("爱尔兰", r"ie|ireland|爱尔兰"), ("墨西哥", r"mx|mexico|墨西哥"),
        ("乌克兰", r"ua|ukraine|乌克兰")
    ]
    for name, pattern in meta:
        if re.search(pattern, text): 
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"
    
    if server in IP_CACHE: 
        return IP_CACHE[server]
    try:
        time.sleep(0.1) 
        response = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=3).json()
        if response.get("status") == "success":
            country = response.get("country")
            icon = EMOJI_MAP.get(country, "🌍")
            label = f"{icon} {country}"
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

    # 精准补全原始中断循环逻辑
    for l in unique_links:
        proxy_data = parse_link(l)
        if not proxy_data:
            continue
            
        label = proxy_data["label"]
        region_map[label].append(proxy_data)
        index = len(region_map[label])
        
        node_name = f"{label} {index:02d} {CHANNEL_MARK}"
        
        if validate_clash_proxy(proxy_data):
            clash_item = proxy_data.copy()
            clash_item["name"] = node_name
            clash_item.pop("label", None)
            clash_item.pop("raw_json", None)
            clash_proxies.append(clash_item)
            
        u = urllib.parse.urlparse(l)
        encoded_name = urllib.parse.quote(node_name)
        new_link = urllib.parse.urlunparse(u._replace(fragment=encoded_name))
        rocket_links.append(new_link)

    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["🔮 自动选择"] + [p["name"] for p in clash_proxies]
            },
            {
                "name": "🔮 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "tolerance": 50,
                "proxies": [p["name"] for p in clash_proxies]
            }
        ],
        "rules": [
            "MATCH,🚀 节点选择"
        ]
    }
    
    with open('clash.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    raw_rocket_text = "\n".join(rocket_links)
    b64_rocket_text = base64.b64encode(raw_rocket_text.encode('utf-8')).decode('utf-8')
    
    with open('shadowrocket.txt', 'w', encoding='utf-8') as f:
        f.write(b64_rocket_text)

    print(f"处理完成：Clash 节点 {len(clash_proxies)} 个，Rocket 链接 {len(rocket_links)} 个。")

if __name__ == "__main__":
    main()
