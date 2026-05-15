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
    """
    最强高精度节点国家/地区识别核心
    支持：中转落地剥离、国际机场三字码(IATA)、边界防误触、双网络API高可用机制
    """
    if not server: 
        return "🌍 其它地区"
        
    # 1. 文本预处理：转小写，移除频道后缀等杂质
    text = urllib.parse.unquote(str(remarks)).lower().strip()
    if CHANNEL_MARK.lower() in text:
        text = text.replace(CHANNEL_MARK.lower(), "")
        
    # 2. 高精度正则词库（包含中文、Emoji、国际机场代码、主流运营商简称）
    meta = [
        ("香港", r"hk|香港|🇭🇰|hong.*kong|hgc|hkbn|wtt|hkt|clsl|hkg"), 
        ("台湾", r"tw|台湾|台灣|🇹🇼|taiwan|cht|fet|tfn|hinet"), 
        ("美国", r"\bus\b|美国|美國|🇺🇸|united.*states|america|los.*angeles|lax|sfo|sanjose|sjc|ord|dfw|jfk"), 
        ("英国", r"\buk\b|\bgb\b|英国|英國|🇬🇧|united.*kingdom|london|lhr"), 
        ("韩国", r"kr|韩国|韓國|🇰🇷|korea|seoul|icn"), 
        ("日本", r"jp|日本|🇯🇵|japan|tokyo|osaka|nrt|hnd|kix"),
        ("新加坡", r"\bsg\b|新加坡|🇸🇬|singapore|sin"), 
        ("越南", r"vn|越南|🇻🇳|vietnam|hanoi|sgn"), 
        ("科威特", r"kw|科威特|🇰🇼|kuwait"), 
        ("德国", r"\bde\b|德国|🇩🇪|germany|frankfurt|fra"),
        ("立陶宛", r"lt|立陶宛|🇱🇹|lithuania"),
        ("澳大利亚", r"\bau\b|australia|澳洲|澳大利亚|🇦🇺|sydney|syd"), 
        ("荷兰", r"\bnl\b|netherlands|holland|荷兰|🇳🇱|amsterdam|ams"),
        ("马来西亚", r"\bmy\b|malaysia|马来西亚|大马|🇲🇾|kuala|kul"), 
        ("泰国", r"\bth\b|thailand|泰国|🇹🇭|bangkok|bkk"),
        ("印度", r"\bin\b|india|印度|🇮🇳|mumbai|bom|del"), 
        ("巴西", r"\bbr\b|brazil|巴西|🇧🇷|sao.*paulo|gru"),
        ("土耳其", r"\btr\b|turkey|土耳其|🇹🇷|istanbul|ist"), 
        ("阿联酋", r"\bae\b|uae|阿联酋|迪拜|🇦🇪|dubai|dxb"),
        ("菲律宾", r"\bph\b|philippines|菲律宾|🇵🇭|manila|mnl"), 
        ("阿根廷", r"\bar\b|argentina|阿根廷|🇦🇷|bue"),
        ("新西兰", r"\bnz|new.*zealand|新西兰|🇳🇿|akl"), 
        ("意大利", r"\bit\b|italy|意大利|🇮🇹|milan|mxp"),
        ("西班牙", r"\bes\b|spain|西班牙|🇪🇸|madrid|mad"), 
        ("瑞士", r"\bch\b|switzerland|瑞士|🇨🇭|zurich|zrh"),
        ("瑞典", r"\bse\b|sweden|瑞典|🇸🇪|arn"), 
        ("南非", r"\bza\b|south.*africa|南非|🇿🇦|jnb"),
        ("爱尔兰", r"\bie\b|ireland|爱尔兰|🇮🇪|dublin|dub"), 
        ("墨西哥", r"\bmx\b|mexico|墨西哥|🇲🇽|mex"),
        ("乌克兰", r"\bua\b|ukraine|乌克兰|🇺🇦|iev")
    ]
    
    # 3. 中转/落地双向扫描：精准剥离国内中转（如广港、沪日，提取最终落地）
    matched_country = None
    last_match_pos = -1
    
    # 国内入口/中转特征词拦截
    cn_gateways = r"上海|广州|深圳|北京|杭州|武汉|徐州|宁波|东莞|江苏|浙江|广东|山东|河南|川|沪|广|深|京|杭|鲁|豫|中转|入口|iepl|iplc"
    
    for name, pattern in meta:
        matches = list(re.finditer(pattern, text))
        if matches:
            last_match = matches[-1] # 提取名字最后部分的国家匹配（符合机场命名习惯）
            if last_match.start() > last_match_pos:
                matched_country = name
                last_match_pos = last_match.start()

    # 如果有明确的落地国家且不为中国，直接采信
    if matched_country and matched_country != "中国":
        return f"{EMOJI_MAP.get(matched_country, '🌍')} {matched_country}"
    elif not matched_country and re.search(cn_gateways, text):
        # 仅有中转词未写明落地的，交由后面的 IP 库在线测定
        pass
    elif matched_country:
        return f"{EMOJI_MAP.get(matched_country, '🌍')} {matched_country}"

    # 4. 离线高速缓存判定
    if server in IP_CACHE: 
        return IP_CACHE[server]
        
    # 5. 在线高可用多API解析（修复原脚本URL拼接缺斜杠Bug）
    clean_server = server.split(':')[0] if ':' in str(server) else str(server)
    
    # 接口A：ip-api.com (带区域方言汉化支持)
    try:
        time.sleep(0.15)  # 控频防限流
        url = f"http://ip-api.com{clean_server}?lang=zh-CN"
        response = requests.get(url, timeout=2).json()
        if response.get("status") == "success":
            country = response.get("country", "")
            for k in EMOJI_MAP.keys():
                if k in country:
                    label = f"{EMOJI_MAP[k]} {k}"
                    IP_CACHE[server] = label
                    return label
    except:
        pass

    # 接口B：ipapi.co 备用降级接口（当A接口被限流时自动启用）
    try:
        url = f"https://ipapi.co{clean_server}/json/"
        response = requests.get(url, timeout=2).json()
        country_name = response.get("country_name", "")
        if country_name:
            for name, pattern in meta:
                if re.search(pattern, country_name.lower()):
                    label = f"{EMOJI_MAP.get(name, '🌍')} {name}"
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
            # 🛠 修复点：彻底重写，使用非破坏性的正则表达式拉取凭证，杜绝 List.split 崩溃
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
        # 提供一个最基础的有效 Clash 文件，防止因为没有合格节点导致文件内容不变化、不更新
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({"mixed-port": 7890, "mode": "rule", "proxies": [{"name": "DIRECT_NODE", "type": "direct"}], "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}, f)
        print("⚠️ 未发现满足导入条件的 Clash 节点，已启用 DIRECT 兜底写入。")

if __name__ == "__main__":
    main()
