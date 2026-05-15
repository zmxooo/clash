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
    ("美国", r"US|USA|UNITED STATES|美国|美國|洛杉矶|圣何塞|GIA"),
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
    """移除所有非 Base64 有效字符，并强制补齐等号"""
    if not s: 
        return ""
    s = re.sub(r'[^a-zA-Z0-9+/=_-]', '', str(s)) # 过滤非法字符，转成标准 Base64 字符集
    s = s.replace('-', '+').replace('_', '/') # 兼容 urlsafe base64
    return s + '=' * (-len(s) % 4)

def safe_b64decode(s):
    """安全的 Base64 解码，确保即使损坏也不抛出致命异常"""
    try:
        fixed = fix_base64(s)
        return base64.b64decode(fixed).decode('utf-8', 'ignore')
    except:
        return ""

def get_region_from_rules(remarks, host):
    """安全提取规则，防止 None 对象触发异常"""
    text = f"{urllib.parse.unquote(str(remarks or ''))} {str(host or '')}".upper()
    for name, pattern in RULES:
        if re.search(pattern, text):
            return name
    return None

def fetch_ip_api(server):
    """API 区域请求拦截与回落"""
    if not server:
        return "", "其它"
    server_str = str(server)
    if server_str in IP_CACHE: 
        return server_str, IP_CACHE[server_str]
    
    # 纯域名后缀前置快速拦截
    if server_str.endswith('.hk'): return server_str, "香港"
    if server_str.endswith('.tw'): return server_str, "台湾"
    if server_str.endswith('.jp'): return server_str, "日本"
    
    try:
        url = f"http://ip-api.com{urllib.parse.quote(server_str)}?lang=zh-CN"
        r = requests.get(url, timeout=3.5).json()
        if isinstance(r, dict) and r.get("status") == "success":
            country = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in country:
                    return server_str, name
            return server_str, country
    except:
        pass
    return server_str, "其它"

def process_node_region(link):
    """解析节点基本信息（加装全局隔离，确保单节点损坏不扩散）"""
    try:
        if not link or "://" not in link:
            return link, "其它", "", ""
            
        host, raw_rem = "", ""
        if link.startswith('vmess://'):
            # 兼容带备注和不带备注的 vmess 拆分
            b64_part = link[8:].split('#')[0]
            decoded = safe_b64decode(b64_part)
            if decoded:
                d = json.loads(decoded)
                host, raw_rem = d.get("add", ""), d.get("ps", "")
        else:
            u = urllib.parse.urlparse(link)
            host = u.hostname or ""
            raw_rem = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
        
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
    
    # 隔离线程池内部崩溃
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_node_region, link): link for link in links}
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
    region_proxies_map = defaultdict(list)
    
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                if link.startswith('vmess://'):
                    b64_part = link[8:].split('#')[0]
                    decoded = safe_b64decode(b64_part)
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
                    region_proxies_map[reg].append(new_name)
                    
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname or "", "port": u.port or 443, "udp": True}
                    queries = dict(urllib.parse.parse_qsl(u.query or ""))
                    
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({"type": "hysteria2", "password": u.username or "", "up": queries.get("up", "20 Mbps"), "down": queries.get("down", "100 Mbps"), "skip-cert-verify": True})
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)
                        region_proxies_map[reg].append(new_name)
                    elif u.scheme == "vless":
                        p.update({"type": "vless", "uuid": u.username or "", "tls": True if queries.get("security") == "tls" or u.port == 443 else False, "skip-cert-verify": True, "network": queries.get("type", "tcp")})
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        region_proxies_map[reg].append(new_name)
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        try:
                            user_info = u.username if "@" in u.netloc else u.netloc.split('#')[0]
                            dec_user = safe_b64decode(user_info)
                            if ":" in dec_user:
                                p["cipher"], p["password"] = dec_user.split(':', 1)
                                clash_proxies.append(p)
                                region_proxies_map[reg].append(new_name)
                        except: pass
                    
                    # 修复处：采用正确的原连接前缀分割，并拼接新备注
                    raw_url_part = link.split('#')[0]
                    final_links.append(f"{raw_url_part}#{urllib.parse.quote(new_name)}")
            except:
                continue

    # 写入 index.html (Base64)
    if final_links:
        try:
            with open('index.html', 'w', encoding='utf-8') as f:
                f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))
        except: pass

    # 写入 config.yaml (Clash)
    if clash_proxies:
        try:
            all_p_names = [p["name"] for p in clash_proxies]
            regional_groups = []
            regional_group_names = []
            
            for reg_name, nodes in region_proxies_map.items():
                if nodes:
                    g_name = f"⚡ {reg_name}自动"
                    regional_group_names.append(g_name)
                    regional_groups.append({
                        "name": g_name, "type": "url-test", "url": "http://gstatic.com",
                        "interval": 300, "tolerance": 50, "proxies": nodes
                    })

            core_groups = [
                {"name": "🛑 广告拦截", "type": "select", "proxies": ["REJECT", "DIRECT", "🚀 节点选择"]},
                {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + regional_group_names + all_p_names},
                {"name": "♻️ 自动选择", "type": "url-test", "url": "http://gstatic.com", "interval": 300, "tolerance": 50, "proxies": all_p_names},
                {"name": "📢 谷歌服务", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择", "DIRECT"] + regional_group_names},
                {"name": "🎬 国际媒体", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择"] + regional_group_names},
                {"name": "🎥 奈飞视频", "type": "select", "proxies": ["🚀 节点选择", "🎬 国际媒体"] + [g for g in regional_group_names if any(k in g for k in ["香港", "台湾", "新加坡", "日本"])]},
                {"name": "📱 电报消息", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择"] + regional_group_names},
                {"name": "🤖 人工智能", "type": "select", "proxies": ["🚀 节点选择"] + [g for g in regional_group_names if any(k in g for k in ["美国", "日本", "新加坡"])]},
                {"name": "🍎 苹果服务", "type": "select", "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"]},
                {"name": "🎯 台湾媒体", "type": "select", "proxies": [g for g in regional_group_names if "台湾" in g] + ["🚀 节点选择", "DIRECT"]},
                {"name": "🐼 国内媒体", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
                {"name": "⚓ 直连域名", "type": "select", "proxies": ["DIRECT", "🚀 节点选择"]},
                {"name": "🌍 漏网之鱼", "type": "select", "proxies": ["🚀 节点选择", "♻️ 自动选择", "DIRECT"]}
            ]

            # 剔除由于某些特定国家完全没节点时，规则分配中产生的空子组引用
            for cg in core_groups:
                cg["proxies"] = [p for p in cg["proxies"] if p]

            conf = {
                "proxies": clash_proxies,
                "proxy-groups": core_groups + regional_groups,
                "rule-providers": {
                    "reject": {"type": "http", "behavior": "domain", "url": "https://jsdelivr.net", "path": "./ruleset/reject.yaml", "interval": 86400},
                    "telegram": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/telegram.yaml", "interval": 86400},
                    "netflix": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/netflix.yaml", "interval": 86400},
                    "bilibili": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/bilibili.yaml", "interval": 86400},
                    "proxy": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/proxy.yaml", "interval": 86400},
                    "google": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/google.yaml", "interval": 86400},
                    "apple": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/apple.yaml", "interval": 86400},
                    "direct": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/direct.yaml", "interval": 86400},
                    "gcland": {"type": "http", "behavior": "classical", "url": "https://jsdelivr.net", "path": "./ruleset/gcland.yaml", "interval": 86400}
                },
                "rules": [
                    "RULE-SET,reject,🛑 广告拦截", "RULE-SET,telegram,📱 电报消息", "RULE-SET,netflix,🎥 奈飞视频",
                    "RULE-SET,bilibili,🐼 国内媒体", "DOMAIN-KEYWORD,openai,🤖 人工智能", "DOMAIN-KEYWORD,anthropic,🤖 人工智能",
                    "DOMAIN-KEYWORD,chatgpt,🤖 人工智能", "DOMAIN-SUFFIX,tw,🎯 台湾媒体", "RULE-SET,google,📢 谷歌服务",
                    "RULE-SET,apple,🍎 苹果服务", "RULE-SET,proxy,🎬 国际媒体", "RULE-SET,direct,⚓ 直连域名",
                    "RULE-SET,gcland,⚓ 直连域名", "GEOIP,CN,DIRECT", "MATCH,🌍 漏网之鱼"
                ]
            }
            
            with open('config.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(conf, f, allow_unicode=True, sort_keys=False)
        except:
            pass

if __name__ == "__main__":
    main()
