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
    s = "".join(str(s).split()) 
    return s + '=' * (-len(s) % 4)

def safe_b64decode(s):
    """安全 Base64 解码沙盒，规避损坏字符串引起的报错"""
    try:
        fixed = fix_base64(s)
        return base64.b64decode(fixed).decode('utf-8', 'ignore')
    except:
        return ""

def get_region_from_rules(remarks, host):
    """第一阶段：纯文本纯正则规则快速匹配（零网络开销）"""
    text = f"{urllib.parse.unquote(str(remarks or ''))} {str(host or '')}".upper()
    for name, pattern in RULES:
        if re.search(pattern, text):
            return name
    return None

def fetch_ip_api(server):
    """通过 API 查询单个 IP 的区域"""
    if not server: return "", "其它"
    srv_str = str(server)
    if srv_str in IP_CACHE: 
        return srv_str, IP_CACHE[srv_str]
        
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
    """解析节点基本信息并识别区域（供线程池调用）"""
    try:
        if not link or "://" not in link:
            return link, "其它", "", ""
            
        host, raw_rem = "", ""
        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            decoded = safe_b64decode(b64_part)
            if decoded:
                d = json.loads(decoded)
                host, raw_rem = d.get("add", ""), d.get("ps", "")
        else:
            u = urllib.parse.urlparse(link)
            host = u.hostname or ""
            # 安全防护：严格进行边界长度检查，彻底修复 link.split('#')[1] 的 IndexError 崩溃
            hash_parts = link.split('#')
            raw_rem = urllib.parse.unquote(hash_parts[1]) if len(hash_parts) > 1 else ""
        
        region = get_region_from_rules(raw_rem, host)
        if region:
            return link, region, host, raw_rem
            
        return link, "NEED_API", host, raw_rem
    except:
        # 对齐返回值：确保异常捕获后仍为 4 元组，防止外部 res[1] 触发 TypeError
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
                if isinstance(res, (tuple, list)) and len(res) >= 4:
                    first_stage_results.append(res)
                    if res[1] == "NEED_API" and res[2]:
                        api_query_servers.add(res[2])
            except:
                continue

    # 并发查询 IP API（带每秒频控，防止单 IP 触发 429）
    if api_query_servers:
        with ThreadPoolExecutor(max_workers=3) as api_executor: 
            api_futures = []
            for srv in api_query_servers:
                if srv:
                    api_futures.append(api_executor.submit(fetch_ip_api, srv))
                
            for fut in as_completed(api_futures):
                try:
                    srv, reg = fut.result()
                    if srv: IP_CACHE[srv] = reg
                except:
                    continue

    # 根据最终分类结果归类节点
    classified_nodes = defaultdict(list)
    for link, region, host, raw_rem in first_stage_results:
        if region == "NEED_API":
            region = IP_CACHE.get(host, "其它")
        classified_nodes[region].append(link)

    final_links, clash_proxies = [], []
    sorted_regions = sorted(classified_nodes.keys())
    
    # 生成节点配置
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
                    
                elif "://" in link:
                    u = urllib.parse.urlparse(link)
                    p = {"name": new_name, "server": u.hostname or "", "port": u.port or 443, "udp": True}
                    queries = dict(urllib.parse.parse_qsl(u.query or ""))
                    
                    # --- 完全补全残缺的全部协议分支 ---
                    if u.scheme in ["hy2", "hysteria2"]:
                        p.update({
                            "type": "hysteria2", "password": u.username or "", 
                            "up": queries.get("up", "20 Mbps"), "down": queries.get("down", "100 Mbps"), 
                            "skip-cert-verify": True
                        })
                        if "sni" in queries: p["sni"] = queries["sni"]
                        clash_proxies.append(p)
                        
                    elif u.scheme == "vless":
                        p.update({
                            "type": "vless", "uuid": u.username or "", 
                            "tls": True if queries.get("security") == "tls" or u.port == 443 else False, 
                            "skip-cert-verify": True, "network": queries.get("type", "tcp")
                        })
                        if "flow" in queries: p["flow"] = queries["flow"]
                        if "sni" in queries: p["sni"] = queries["sni"]
                        if queries.get("type") == "ws":
                            p["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", p["server"])}}
                        clash_proxies.append(p)
                        
                    elif u.scheme in ["ss", "shadowsocks"]:
                        # 兼容处理标准旧版明文格式与 Base64 复合格式
                        if u.username and ":" in safe_b64decode(u.username):
                            userinfo = safe_b64decode(u.username).split(":", 1)
                            method, password = userinfo[0], userinfo[1]
                        else:
                            method = queries.get("method", "aes-256-gcm")
                            password = u.username or ""
                        p.update({
                            "type": "ss", "cipher": method, "password": password
                        })
                        clash_proxies.append(p)

                    elif u.scheme == "trojan":
                        p.update({
                            "type": "trojan", "password": u.username or "",
                            "sni": queries.get("sni", p["server"]), "skip-cert-verify": True
                        })
                        clash_proxies.append(p)
            except:
                continue

    # 将生成的 Clash 配置就地输出（利用开头导入的 yaml 库）
    if clash_proxies:
        with open('output_clash.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"proxies": clash_proxies}, f, allow_unicode=True, sort_keys=False)

if __name__ == '__main__':
    main()
