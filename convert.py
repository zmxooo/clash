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
IP_CACHE_FILE = "ip_cache.json"
MAX_WORKERS = 10  # 并发线程数

# 同步的目标文件定义
INDEX_FILE = "index.html"
CONFIG_FILE = "config.yaml"

# 统一测速参数
TEST_URL = "http://gstatic.com"
TEST_INTERVAL = 300

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

if os.path.exists(IP_CACHE_FILE):
    try:
        with open(IP_CACHE_FILE, 'r', encoding='utf-8') as f:
            IP_CACHE = json.load(f)
    except:
        IP_CACHE = {}
else:
    IP_CACHE = {}

def fix_base64(s):
    if not s: return ""
    s = "".join(s.split()) 
    return s + '=' * (-len(s) % 4)

def get_region_from_rules(remarks, host):
    text = f"{urllib.parse.unquote(str(remarks))} {host}".upper()
    for name, pattern in RULES:
        if re.search(pattern, text):
            return name
    return None

def fetch_ip_api(server):
    if server in IP_CACHE: 
        return server, IP_CACHE[server]
        
    if server.endswith('.hk'): return server, "香港"
    if server.endswith('.tw'): return server, "台湾"
    if server.endswith('.jp'): return server, "日本"
    
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", server) and "." in server:
        return server, "其它"

    try:
        time.sleep(1.3)
        url = f"http://ip-api.com{server}?lang=zh-CN"
        r = requests.get(url, timeout=4).json()
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
    try:
        host, raw_rem = "", ""
        if link.startswith('vmess://'):
            b64 = link[8:].split('#')
            d = json.loads(base64.b64decode(fix_base64(b64)).decode('utf-8', 'ignore'))
            host, raw_rem = d.get("add"), d.get("ps")
        else:
            u = urllib.parse.urlparse(link)
            host = u.hostname or ""
            raw_rem = urllib.parse.unquote(link.split('#')) if '#' in link else ""
        
        region = get_region_from_rules(raw_rem, host)
        if region:
            return link, region, host, raw_rem
            
        return link, "NEED_API", host, raw_rem
    except:
        return link, "其它", "", ""

def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt，无法执行同步更新。")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        links = list(dict.fromkeys([l.strip() for l in f if "://" in l]))

    first_stage_results = []
    api_query_servers = set()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_node_region, link) for link in links]
        for fut in as_completed(futures):
            res = fut.result()
            first_stage_results.append(res)
            if res == "NEED_API" and res:
                api_query_servers.add(res)

    if api_query_servers:
        with ThreadPoolExecutor(max_workers=1) as api_executor: 
            api_futures = [api_executor.submit(fetch_ip_api, srv) for srv in api_query_servers]
            for fut in as_completed(api_futures):
                srv, reg = fut.result()
                IP_CACHE[srv] = reg
        
        try:
            with open(IP_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(IP_CACHE, f, ensure_ascii=False, indent=2)
        except: 
            pass

    classified_nodes = defaultdict(list)
    for link, region, host, raw_rem in first_stage_results:
        if region == "NEED_API":
            region = IP_CACHE.get(host, "其它")
        classified_nodes[region].append(link)

    final_links, clash_proxies = [], []
    region_proxy_map = defaultdict(list)  # 按国家划分节点名称列表
    all_proxy_names = []                 
    sorted_regions = sorted(classified_nodes.keys())
    
    for reg in sorted_regions:
        for idx, link in enumerate(classified_nodes[reg], 1):
            new_name = f"{EMOJI_MAP.get(reg, '🌍')}{reg} {FIXED_SUFFIX}{idx}"
            
            try:
                if link.startswith('vmess://'):
                    b64 = link[8:].split('#')
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
                    region_proxy_map[reg].append(new_name)
                    all_proxy_names.append(new_name)
                    
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {
                        "name": new_name, 
                        "server": u.hostname, 
                        "port": u.port or (443 if u.scheme in ["hy2", "hysteria2", "vless"] else 80), 
                        "udp": True
                    }
                    queries = dict(urllib.parse.parse_qsl(u.query))
                    
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({
                            "type": "hysteria2", 
                            "password": u.username or u.netloc.split('@'), 
                            "up": queries.get("up", "20 Mbps"), 
                            "down": queries.get("down", "100 Mbps"), 
                            "skip-cert-verify": True
                        })
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)
                        region_proxy_map[reg].append(new_name)
                        all_proxy_names.append(new_name)
                        final_links.append(f"{u.scheme}://{p['password']}@{p['server']}:{p['port']}?{urllib.parse.urlencode(queries)}#{urllib.parse.quote(new_name)}")
                        
                    elif u.scheme == "vless":
                        p.update({
                            "type": "vless", "uuid": u.username or u.netloc.split('@'), 
                            "tls": True if queries.get("security") == "tls" or u.port == 443 else False, 
                            "skip-cert-verify": True,
                            "network": queries.get("type", "tcp")
                        })
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        region_proxy_map[reg].append(new_name)
                        all_proxy_names.append(new_name)
                        final_links.append(f"vless://{p['uuid']}@{p['server']}:{p['port']}?{urllib.parse.urlencode(queries)}#{urllib.parse.quote(new_name)}")
                        
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p["type"] = "ss"
                        user_info = u.netloc.split('@') if "@" in u.netloc else u.netloc.split('#')
                        try:
                            dec_user = base64.b64decode(fix_base64(user_info)).decode('utf-8', 'ignore')
                            if ":" in dec_user:
                                p["cipher"], p["password"] = dec_user.split(':', 1)
                                clash_proxies.append(p)
                                region_proxy_map[reg].append(new_name)
                                all_proxy_names.append(new_name)
                                final_links.append(f"ss://{user_info}@{p['server']}:{p['port']}#{urllib.parse.quote(new_name)}")
                        except:
                            pass
            except:
                pass

    # 1. 覆盖同步 index.html
    if final_links:
        with open(INDEX_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_links))

    # 2. 彻底重新生成 config.yaml (完全抛弃历史损坏框架)
    if clash_proxies:
        try:
            # --- 代码内置高标准基础骨架 ---
            base_config = {
                "port": 7890,
                "socks-port": 7891,
                "allow-lan": True,
                "mode": "rule",
                "log-level": "info",
                "external-controller": "127.0.0.1:9090",
                "dns": {
                    "enable": True,
                    "ipv6": False,
                    "listen": "0.0.0.0:53",
                    "enhanced-mode": "fake-ip",
                    "fake-ip-range": "198.18.0.1/16",
                    "default-nameserver": ["119.29.29.29", "223.5.5.5"],
                    "nameserver": ["https://doh.pub", "https://alicdn.com"]
                }
            }
                
            # 填入最新清洗完的纯净节点
            base_config["proxies"] = clash_proxies
            
            # --- 核心设计：重组全自动动态测速分组 ---
            new_groups = []
            dynamic_country_group_names = []
            
            # A. 遍历当前生成的所有国家，动态建立独立国家的 url-test 分组
            # 这能完美确保在工具首页，每个国家只展示最快的那一个名字
            for r_name in sorted(region_proxy_map.keys()):
                emoji = EMOJI_MAP.get(r_name, '🌍')
                group_title = f"{emoji} {r_name}自动选择"
                dynamic_country_group_names.append(group_title)
                
                new_groups.append({
                    "name": group_title,
                    "type": "url-test",
                    "url": TEST_URL,
                    "interval": TEST_INTERVAL,
                    "proxies": region_proxy_map[r_name]
                })
            
            # B. 建立总控“♻️ 自动选择”分组 (包含所有生成的节点)
            new_groups.append({
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": TEST_INTERVAL,
                "proxies": all_proxy_names
            })
            
            # C. 看板首页总控栏 (包含全局自动选择，各个国家的分组选择以及直连)
            new_groups.insert(0, {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择"] + dynamic_country_group_names + ["DIRECT"]
            })
            
            base_config["proxy-groups"] = new_groups
            
            # --- 配置通用分流规则流 ---
            base_config["rules"] = [
                "MATCH,🚀 节点选择"
            ]
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(base_config, f, allow_unicode=True, sort_keys=False)
            print(f"配置文件已彻底完成重构刷新：{CONFIG_FILE}，所有冲突已清除！")
        except Exception as e:
            print(f"同步失败: {e}")

if __name__ == '__main__':
    main()
