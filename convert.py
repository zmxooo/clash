import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置参数 ---
FIXED_SUFFIX = "zmxooo"
IP_CACHE = {}
MAX_WORKERS = 10  # 并发线程数

RULES = [
    ("香港", r"HK|HONGKONG|香港|廣港|CMI|HKT|PCCW|HGC|WTT"),
    ("台湾", r"TW|TAIWAN|台湾|台灣|彰化|台北|CHT"),
    ("日本", r"JP|JAPAN|日本|东京|大阪|東京|大阪|NTT|KDDI"),
    ("韩国", r"KR|KOREA|韩国|韓國|首尔|首爾|SK|KT"),
    ("新加坡", r"SG|SINGAPORE|新加坡|AWS-SG"),
    ("美国", r"US|USA|UNITED STATES|美国|美國|洛杉矶|圣开塞|圣何塞|GIA"),
    ("英国", r"UK|GB|UNITED KINGDOM|英国|英國|伦敦"),
    ("德国", r"DE|GERMANY|德国|德國|法兰克福"),
    ("俄罗斯", r"RU|RUSSIA|俄罗斯|俄羅斯|伯力|莫斯科"),
    ("越南", r"VN|VIETNAM|越南"),
    ("泰国", r"TH|THAILAND|泰国")
]

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "日本": "🇯🇵", "韩国": "🇰🇷", "新加坡": "🇸🇬", 
    "美国": "🇺🇸", "英国": "🇬🇧", "德国": "🇩🇪", "俄罗斯": "🇷🇺", "越南": "🇻🇳", "泰国": "🇹🇭", "其它": "🌍"
}

def fix_base64(s):
    """清洗非 Base64 规范字符并强制补齐等号"""
    if not s: return ""
    s = re.sub(r'[^a-zA-Z0-9+/=_-]', '', str(s))
    s = s.replace('-', '+').replace('_', '/')
    return s + '=' * (-len(s) % 4)

def safe_b64decode(s):
    """安全的 Base64 解码沙盒，规避损坏字符串引起的报错"""
    try:
        fixed = fix_base64(s)
        return base64.b64decode(fixed).decode('utf-8', 'ignore')
    except:
        return ""

def get_region_from_rules(remarks, host):
    """安全拼合文本防止 None 对象引发异常"""
    text = f"{urllib.parse.unquote(str(remarks or ''))} {str(host or '')}".upper()
    for name, pattern in RULES:
        if re.search(pattern, text):
            return name
    return None

def fetch_ip_api(server):
    """API 区域请求与缓存过滤"""
    if not server: return "", "其它"
    srv_str = str(server)
    if srv_str in IP_CACHE: return srv_str, IP_CACHE[srv_str]
    if srv_str.endswith('.hk'): return srv_str, "香港"
    if srv_str.endswith('.tw'): return srv_str, "台湾"
    if srv_str.endswith('.jp'): return srv_str, "日本"
    
    try:
        url = f"http://ip-api.com{urllib.parse.quote(srv_str)}?lang=zh-CN"
        r = requests.get(url, timeout=3.5).json()
        if isinstance(r, dict) and r.get("status") == "success":
            country = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in country:
                    return srv_str, name
            return srv_str, country
    except:
        pass
    return srv_str, "其它"

def process_node_region(link):
    """第一阶段节点解析，加装容错机制"""
    try:
        if not link or "://" not in link:
            return link, "其它", "", ""
        
        host, raw_rem = "", ""
        if link.startswith('vmess://'):
            parts = link[8:].split('#')
            decoded = safe_b64decode(parts[0])
            if decoded:
                d = json.loads(decoded)
                host, raw_rem = d.get("add", ""), d.get("ps", "")
        else:
            u = urllib.parse.urlparse(link)
            host = u.hostname or ""
            parts = link.split('#')
            raw_rem = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
        
        region = get_region_from_rules(raw_rem, host)
        if region:
            return link, region, host, raw_rem
        return link, "NEED_API", host, raw_rem
    except:
        return link, "其它", "", ""

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    first_stage_results = []
    api_query_servers = set()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_node_region, link) for link in links]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                first_stage_results.append(res)
                if res[1] == "NEED_API" and res[2]:
                    api_query_servers.add(res[2])
            except:
                continue

    if api_query_servers:
        with ThreadPoolExecutor(max_workers=3) as api_executor:
            api_futures = [api_executor.submit(fetch_ip_api, srv) for srv in api_query_servers if srv]
            for fut in as_completed(api_futures):
                try:
                    srv, reg = fut.result()
                    if srv: IP_CACHE[srv] = reg
                except:
                    continue

    classified_nodes = defaultdict(list)
    for link, region, host, raw_rem in first_stage_results:
        if region == "NEED_API":
            region = IP_CACHE.get(host, "其它")
        classified_nodes[region].append(link)

    final_links, clash_proxies = [], []
    sorted_regions = sorted(classified_nodes.keys())
    
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                # 1. VMESS 协议
                if link.startswith('vmess://'):
                    parts = link[8:].split('#')
                    decoded = safe_b64decode(parts[0])
                    if not decoded: continue
                    d = json.loads(decoded)
                    d["ps"] = new_name
                    new_b64 = base64.b64encode(json.dumps(d, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                    final_links.append(f"vmess://{new_b64}")
                    
                    proxy = {
                        "name": new_name, "type": "vmess", "server": d.get("add", ""), "port": int(d.get("port", 443)),
                        "uuid": d.get("id", ""), "alterId": int(d.get("aid", 0)), "cipher": "auto",
                        "tls": True if str(d.get("tls", "")).lower() in ["tls", "1", "true"] else False,
                        "network": d.get("net", "tcp"), "skip-cert-verify": True
                    }
                    if d.get("net") == "ws":
                        proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
                    clash_proxies.append(proxy)
                    
                # 2. 其他基于标准 URL 格式的协议
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname or "", "port": u.port or 443, "udp": True}
                    queries = dict(urllib.parse.parse_qsl(u.query or ""))
                    
                    # Hysteria2
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({"type": "hysteria2", "password": u.username or "", "up": queries.get("up", "20 Mbps"), "down": queries.get("down", "100 Mbps"), "skip-cert-verify": True})
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)
                        
                    # VLESS
                    elif u.scheme == "vless":
                        p.update({"type": "vless", "uuid": u.username or "", "tls": True if queries.get("security") == "tls" or u.port == 443 else False, "skip-cert-verify": True, "network": queries.get("type", "tcp")})
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        
                    # Trojan (补齐)
                    elif u.scheme == "trojan":
                        p.update({"type": "trojan", "password": u.username or "", "sni": queries.get("sni", p["server"]), "skip-cert-verify": True})
                        if "security" in queries: p["tls"] = True if queries["security"] == "tls" else False
                        if queries.get("type") == "ws":
                            p["network"] = "ws"
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        
                    # Tuic (补齐)
                    elif u.scheme == "tuic":
                        p.update({
                            "type": "tuic", "uuid": u.username or "", "password": u.password or "",
                            "congestion-controller": queries.get("congestion_control", "bbr"),
                            "alpn": [queries.get("alpn", "h3")], "skip-cert-verify": True
                        })
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)

                    # Shadowsocks
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        try:
                            user_info = u.username if "@" in u.netloc else u.netloc.split('#')[0]
                            dec_user = safe_b64decode(user_info)
                            if ":" in dec_user:
                                p["cipher"], p["password"] = dec_user.split(':', 1)
                                clash_proxies.append(p)
                        except: pass
                    
                    base_url = link.split('#')
                    final_links.append(f"{base_url[0]}#{urllib.parse.quote(new_name)}")
            except:
                continue

    # 生成 index.html
    if final_links:
        try:
            with open('index.html', 'w', encoding='utf-8') as f:
                f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))
        except: pass

    # 保持原有极简策略组
    if clash_proxies:
        try:
            p_names = [p["name"] for p in clash_proxies]
            conf = {
                "proxies": clash_proxies,
                "proxy-groups": [
                    {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + p_names},
                    {"name": "♻️ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "proxies": p_names}
                ],
                "rules": ["MATCH,🚀 节点选择"]
            }
            with open('config.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
        except:
            pass

if __name__ == "__main__":
    main()
