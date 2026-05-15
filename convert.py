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
MAX_WORKERS = 10  # 并发线程数，推荐 10-20

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
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def get_region_from_rules(remarks, host):
    """第一阶段：纯文本纯正则规则快速匹配（零网络开销）"""
    text = f"{urllib.parse.unquote(str(remarks))} {host}".upper()
    for name, pattern in RULES:
        if re.search(pattern, text):
            return name
    return None

def fetch_ip_api(server):
    """通过 API 查询单个 IP 的区域"""
    if server in IP_CACHE: 
        return server, IP_CACHE[server]
        
    # 过滤掉域名，只对 IP 或无法匹配规则的进行查询
    # 如果是纯域名且带国家后缀，做简单前置拦截
    if server.endswith('.hk'): return server, "香港"
    if server.endswith('.tw'): return server, "台湾"
    if server.endswith('.jp'): return server, "日本"
    
    try:
        # 使用 ip-api.com，限流为 45 req/min
        url = f"http://ip-api.com/json/{server}?lang=zh-CN"
        r = requests.get(url, timeout=3.5).json()
        if r.get("status") == "success":
            country = r.get("country", "")
            for name in EMOJI_MAP.keys():
                if name in country:
                    return server, name
            return server, country
    except:
        pass
    return server, "其它"

def process_node_region(link):
    """解析节点基本信息并识别区域（供线程池调用）"""
    try:
        host, raw_rem = "", ""
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')[0]
            d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
            host, raw_rem = d.get("add"), d.get("ps")
        else:
            u = urllib.parse.urlparse(link)
            host = u.hostname or ""
            raw_rem = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
        
        # 1. 优先正则匹配
        region = get_region_from_rules(raw_rem, host)
        if region:
            return link, region, host, raw_rem
            
        # 2. 正则未命中，返回标记，后续批量交由 API 识别
        return link, "NEED_API", host, raw_rem
    except:
        return link, "其它", "", ""

def main():
    if not os.path.exists('nodes.txt'):
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    # 步骤 1：利用多线程并发解析节点，并提取出需要调用 API 查询的 IP
    first_stage_results = []
    api_query_servers = set()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_node_region, link) for link in links]
        for fut in as_completed(futures):
            res = fut.result()
            first_stage_results.append(res)
            if res[1] == "NEED_API" and res[2]:
                api_query_servers.add(res[2])

    # 步骤 2：并发查询 IP API（带每秒频控，防止单 IP 触发 429）
    if api_query_servers:
        with ThreadPoolExecutor(max_workers=3) as api_executor: # 查询 API 降速到 3 线程，规避限流
            api_futures = []
            for idx, srv in enumerate(api_query_servers):
                # 稍微交错请求时间
                api_futures.append(api_executor.submit(fetch_ip_api, srv))
                
            for fut in as_completed(api_futures):
                srv, reg = fut.result()
                IP_CACHE[srv] = reg

    # 步骤 3：根据最终分类结果归类节点
    classified_nodes = defaultdict(list)
    for link, region, host, raw_rem in first_stage_results:
        if region == "NEED_API":
            region = IP_CACHE.get(host, "其它")
        classified_nodes[region].append(link)

    final_links, clash_proxies = [], []
    sorted_regions = sorted(classified_nodes.keys())
    
    # 步骤 4：生成节点配置
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                if link.startswith('vmess://'):
                    b64 = link[8:].split('#')[0]
                    d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
                    d["ps"] = new_name
                    new_b64 = base64.b64encode(json.dumps(d, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                    final_links.append(f"vmess://{new_b64}")
                    
                    proxy = {
                        "name": new_name, "type": "vmess", "server": d["add"], "port": int(d["port"]),
                        "uuid": d["id"], "alterId": int(d.get("aid", 0)), "cipher": "auto",
                        "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                        "network": d.get("net", "tcp"), "skip-cert-verify": True
                    }
                    if d.get("net") == "ws":
                        proxy["ws-opts"] = {"path": d.get("path", ""), "headers": {"Host": d.get("host", "")}}
                    clash_proxies.append(proxy)
                    
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname, "port": u.port or 443, "udp": True}
                    
                    # 提取 URL 参数
                    queries = dict(urllib.parse.parse_qsl(u.query))
                    
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({
                            "type": "hysteria2", 
                            "password": u.username, 
                            "up": queries.get("up", "20 Mbps"), 
                            "down": queries.get("down", "100 Mbps"), 
                            "skip-cert-verify": True
                        })
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)
                        
                    elif u.scheme == "vless":
                        p.update({
                            "type": "vless", "uuid": u.username, 
                            "tls": True if queries.get("security") == "tls" or u.port == 443 else False, 
                            "skip-cert-verify": True,
                            "network": queries.get("type", "tcp")
                        })
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        try:
                            # 兼容常规 ss://base64 格式 与 新版 ss://base64@host:port 格式
                            if "@" in u.netloc:
                                user_info = u.username
                            else:
                                user_info = u.netloc.split('#')[0]
                            
                            dec_user = base64.b64decode(fix_base64(user_info)).decode('utf-8', 'ignore')
                            if ":" in dec_user:
                                p["cipher"], p["password"] = dec_user.split(':', 1)
                                clash_proxies.append(p)
                        except: 
                            pass
                    
                    final_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}")
            except:
                continue

    # 生成 index.html
    if final_links:
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

    # 生成 config.yaml
    if clash_proxies:
        p_names = [p["name"] for p in clash_proxies]
        conf = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择", "DIRECT"] + p_names},
                {"name": "♻️ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": p_names}
            ],
            "rules": ["MATCH,🚀 节点选择"]
        }
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    main()
