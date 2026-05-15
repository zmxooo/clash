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
        
    if server.endswith('.hk'): return server, "香港"
    if server.endswith('.tw'): return server, "台湾"
    if server.endswith('.jp'): return server, "日本"
    
    try:
        url = f"http://ip-api.com{server}?lang=zh-CN"
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
        
        region = get_region_from_rules(raw_rem, host)
        if region:
            return link, region, host, raw_rem
            
        return link, "NEED_API", host, raw_rem
    except:
        return link, "Miami", "", ""

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
            res = fut.result()
            first_stage_results.append(res)
            if res[1] == "NEED_API" and res[2]:
                api_query_servers.add(res[2])

    if api_query_servers:
        with ThreadPoolExecutor(max_workers=3) as api_executor: 
            api_futures = []
            for idx, srv in enumerate(api_query_servers):
                api_futures.append(api_executor.submit(fetch_ip_api, srv))
                
            for fut in as_completed(api_futures):
                srv, reg = fut.result()
                IP_CACHE[srv] = reg

    classified_nodes = defaultdict(list)
    for link, region, host, raw_rem in first_stage_results:
        if region == "NEED_API":
            region = IP_CACHE.get(host, "其它")
        classified_nodes[region].append(link)

    final_links, clash_proxies = [], []
    sorted_regions = sorted(classified_nodes.keys())
    region_to_proxy_names = defaultdict(list)
    
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
                    region_to_proxy_names[reg].append(new_name)
                    
                elif "://" in link:
                    # 协议层优化：清洗链接中多余的空格或隐性异常字符
                    clean_link = link.strip()
                    u = urllib.parse.urlparse(clean_link)
                    queries = dict(urllib.parse.parse_qsl(u.query))
                    
                    # 优先提取核心通用属性
                    server_host = u.hostname or ""
                    server_port = u.port
                    
                    if u.scheme in ["hy2", "hysteria2"]:
                        p = {
                            "name": new_name, "type": "hysteria2", "server": server_host, "port": server_port or 443,
                            "password": u.username or u.netloc.split('@')[0], 
                            "up": queries.get("up", "20 Mbps"), "down": queries.get("down", "100 Mbps"), 
                            "skip-cert-verify": True, "udp": True
                        }
                        if "sni" in queries: p["sni"] = queries["sni"]
                        # 增加 Hysteria2 混淆协议支持
                        if "obfs" in queries:
                            p["obfs"] = queries["obfs"]
                            if "obfs-password" in queries: p["obfs-password"] = queries["obfs-password"]
                        clash_proxies.append(p)
                        region_to_proxy_names[reg].append(new_name)
                        
                    elif u.scheme == "vless":
                        p = {
                            "name": new_name, "type": "vless", "server": server_host, "port": server_port or 443,
                            "uuid": u.username or u.netloc.split('@')[0], "udp": True,
                            "tls": True if queries.get("security") in ["tls", "reality"] or server_port == 443 else False, 
                            "skip-cert-verify": True, "network": queries.get("type", "tcp")
                        }
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        
                        # 增加 VLESS Reality 高级安全扩展映射
                        if queries.get("security") == "reality":
                            p["servername"] = queries.get("sni", "")
                            if "pbk" in queries: p["reality-opts"] = {"public-key": queries["pbk"]}
                            if "sid" in queries: p["reality-opts"]["short-id"] = queries["sid"]
                            
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        elif queries.get("type") == "grpc":
                            p["grpc-opts"] = {"grpc-service-name": queries.get("serviceName", "")}
                            
                        clash_proxies.append(p)
                        region_to_proxy_names[reg].append(new_name)
                        
                    elif u.scheme in ["ss", "shadowsocks"]:
                        p = {"name": new_name, "type": "ss", "udp": True}
                        try:
                            # 协议层优化：双重逻辑兼容新旧及标准/非标准 Base64 复合型 Shadowsocks 链接
                            if "@" in u.netloc:
                                p["server"] = server_host
                                p["port"] = server_port or 8388
                                user_info = u.username or u.netloc.split('@')[0]
                            else:
                                raw_payload = clean_link.split('://')[1].split('#')[0]
                                if "@" in raw_payload:
                                    b64_part, host_part = raw_payload.split('@', 1)
                                    user_info = base64.b64decode(fix_base64(b64_part)).decode('utf-8', 'ignore')
                                    if ":" in host_part:
                                        p["server"] = host_part.split(':')[0]
                                        p["port"] = int(host_part.split(':')[1])
                                    else:
                                        p["server"] = host_part
                                        p["port"] = 8388
                                else:
                                    # 纯全密格式 ss://BASE64
                                    user_info = base64.b64decode(fix_base64(raw_payload)).decode('utf-8', 'ignore')
                                    
                            if ":" in user_info:
                                parts = user_info.split(':', 1)
                                # 区分标准格式 cipher:password 与 host:port 兼容
                                if not p.get("server") and len(parts) > 1 and parts[1].isdigit():
                                    p["server"] = parts[0]
                                    p["port"] = int(parts[1])
                                else:
                                    p["cipher"], p["password"] = parts[0], parts[1]
                                    
                            if "@" in user_info and not p.get("cipher"):
                                c_p, s_p = user_info.split('@', 1)
                                if ":" in c_p: p["cipher"], p["password"] = c_p.split(':', 1)
                                if ":" in s_p: p["server"], p["port"] = s_p.split(':')[0], int(s_p.split(':')[1])
                                
                            if p.get("server") and p.get("cipher"):
                                clash_proxies.append(p)
                                region_to_proxy_names[reg].append(new_name)
                        except:
                            pass
            except:
                pass

    # --- 保持原汁原味的动态国家 URL-Test 自动测速策略组组装 ---
    clash_groups = []
    country_auto_group_names = []
    
    for reg, p_names in region_to_proxy_names.items():
        if not p_names:
            continue
        group_name = f"{EMOJI_MAP.get(reg, '🌍')} {reg}-自动选择"
        country_auto_group_names.append(group_name)
        
        clash_groups.append({
            "name": group_name,
            "type": "url-test",
            "url": "http://gstatic.com",
            "interval": 300,
            "tolerance": 50,
            "proxies": p_names
        })

    all_individual_proxies = [p["name"] for p in clash_proxies]
    main_group = {
        "name": "🚀 节点选择",
        "type": "select",
        "proxies": ["DIRECT"] + country_auto_group_names + all_individual_proxies
    }
    clash_groups.insert(0, main_group)

    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": clash_groups
    }

    with open('clash_proxies.yml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

if __name__ == '__main__':
    main()
