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
                                all_proxy_names.append(new_name)
                                final_links.append(f"ss://{user_info}@{p['server']}:{p['port']}#{urllib.parse.quote(new_name)}")
                        except:
                            pass
            except:
                pass

    if final_links:
        with open(INDEX_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_links))

    # 2. 覆盖同步 config.yaml 并强制纠正代理组
    if clash_proxies:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    base_config = yaml.safe_load(f) or {}
            else:
                base_config = {}
                
            base_config["proxies"] = clash_proxies
            
            # --- 终极防御逻辑：全自动扫描校验你的原始手写策略组 ---
            if "proxy-groups" in base_config and isinstance(base_config["proxy-groups"], list):
                for group in base_config["proxy-groups"]:
                    if "proxies" in group and isinstance(group["proxies"], list):
                        old_list = group["proxies"]
                        cleaned_list = []
                        
                        # 遍历你手写的每个节点或子分组引用
                        for item in old_list:
                            item_str = str(item)
                            
                            # 情况 A：如果该项属于动态生成的节点（带有 zmxooo 后缀）
                            if FIXED_SUFFIX in item_str:
                                # 检查本次运行到底有没有真正生成这个节点
                                if item_str in all_proxy_names:
                                    cleaned_list.append(item_str)  # 生成了，保留
                                else:
                                    # 没生成（比如这次机场没有台湾节点）
                                    # 智能寻找本次生成的同国家其他节点替代，如果没有，用全局第一个节点兜底！
                                    country_prefix = item_str.split(FIXED_SUFFIX)[0].strip()
                                    matched_backups = [n for n in all_proxy_names if country_prefix in n]
                                    if matched_backups:
                                        cleaned_list.append(matched_backups[0])
                                    elif all_proxy_names:
                                        cleaned_list.append(all_proxy_names[0]) # 极限制止 not found 报错
                            else:
                                # 情况 B：属于 DIRECT 或其他子分组名称，保持原样
                                cleaned_list.append(item)
                        
                        # 如果是“自动选择”等主控测速组，将其转换为 url-test，直接透传当前最快节点到代理看板首页
                        if group.get("name") in ["♻️ 自动选择", "自动选择"] or "自动" in group.get("name", ""):
                            group["type"] = "url-test"
                            group["url"] = TEST_URL
                            group["interval"] = TEST_INTERVAL
                            
                        group["proxies"] = cleaned_list
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(base_config, f, allow_unicode=True, sort_keys=False)
            print(f"同步已彻底修复成功：{CONFIG_FILE}")
        except Exception as e:
            print(f"同步失败: {e}")

if __name__ == '__main__':
    main()
