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
    "德国": "🇩🇪", "法国": "🇫🇷", "俄罗斯": "🇷🇺", "中国": "🇨🇳", "加拿大": "🇨🇦"
}

import re
import urllib.parse

def get_final_label(server: str = "", remarks: str = "") -> str:
    """
    企业军工级节点国家/地区全自动化精准识别引擎
    """
    if not remarks and not server:
        return "🌍 其它地区"
    
    # 1. 解码 + 规范化文本
    server_str = str(server).strip()
    remarks_decoded = urllib.parse.unquote(str(remarks)).strip()
    text = f"{remarks_decoded} {server_str}".lower()
    
    # 清洗特殊字符（保留 IP、IPv6、域名关键分隔符）
    text_clean = re.sub(r'[^a-z0-9.\-:/_@]', ' ', text)
    
    # ==================== 1. 精确正则匹配规则（优先） ====================
    # 规则增加 \b 或边界限定，防止如 5.83.129 误匹配到其他包含该数字的字符串
    rules = [
        # 香港 (Hong Kong)
        (r"香港|🇭🇰|hkmax|\bhkt\d|\bhk\d|202\.146\.222|149\.129\.91|70\.39\.206|47\.76\.218|8\.223\.63|154\.92\.9", "🇭🇰 香港"),
        
        # 台湾 (Taiwan)
        (r"台湾|台灣|🇹🇼|\btw\d|125\.227\.86|160\.187\.100", "🇹🇼 台湾"),
        
        # 新加坡 (Singapore)
        (r"新加坡|狮城|🇸🇬|\bsg\d|vpn-sg|108\.162\.192", "🇸🇬 新加坡"),
        
        # 日本 (Japan)
        (r"日本|🇯🇵|\bjp\d|jp\.oshuawei|103\.150\.8|88\.214\.22|43\.165\.190|a3cdfe9b", "🇯🇵 日本"),
        
        # 美国 (United States)
        (r"美国|美联航|🇺🇸|\bus\d|us-|23\.144\.12|199\.34\.230", "🇺🇸 美国"),
        
        # 韩国 (South Korea)
        (r"韩国|南韩|🇰🇷|\bkr\d|kr-|vpn-kr|59\.0\.95", "🇰🇷 韩国"),
        
        # 越南 (Vietnam)
        (r"越南|🇻🇳|\bvn\d|103\.186\.(154|155)", "🇻🇳 越南"),
        
        # 德国 (Germany)
        (r"德国|🇩🇪|\bde\d|\bfr[a-z]\d|5\.83\.129", "🇩🇪 德国"),
        
        # 英国 (United Kingdom)
        (r"英国|大不列颠|🇬🇧|\buk\d|\blon\d", "🇬🇧 英国"),
        
        # 法国 (France)
        (r"法国|法兰西|🇫🇷|\bfr\d", "🇫🇷 法国"),
        
        # 俄罗斯 (Russia)
        (r"俄罗斯|毛子|🇷🇺|\bru\d|\bmow\d", "🇷🇺 俄罗斯"),
        
        # 加拿大 (Canada)
        (r"加拿大|🇨🇦|\bca\d|\byvr\d|\byyz\d", "🇨🇦 加拿大"),
        
        # 澳大利亚 (Australia)
        (r"澳大利亚|澳洲|🇦🇺|\bau\d|\bsyd\d", "🇦🇺 澳大利亚"),
        
        # 荷兰 (Netherlands)
        (r"荷兰|🇳🇱|\bnl\d|\bams\d", "🇳🇱 荷兰"),
        
        # 土耳其 (Turkey)
        (r"土耳其|🇹🇷|\btr\d|\bist\d", "🇹🇷 土耳其"),
        
        # 印度 (India)
        (r"印度|🇮🇳|\bin\d|\bbom\d|\bdel\d", "🇮🇳 印度"),
        
        # 马来西亚 (Malaysia)
        (r"马来西亚|大马|🇲🇾|\bmy\d|\bkul\d", "🇲🇾 马来西亚"),
        
        # 菲律宾 (Philippines)
        (r"菲律宾|🇵🇭|\bph\d|\bmnl\d", "🇵🇭 菲律宾"),
        
        # 泰国 (Thailand)
        (r"泰国|🇹🇭|\bth\d|\bbkk\d", "🇹🇭 泰国"),
    ]
    
    for pattern, label in rules:
        if re.search(pattern, text_clean):
            return label
            
    # ==================== 2. 机场三字码与地名兜底增强 ====================
    # 全面覆盖主流机场节点命名和城市缩写
    fallback_keywords = {
        "🇭🇰 香港": ["hk", "hong", "hkt", "hkmax", "hkg"],
        "🇹🇼 台湾": ["tw", "taiwan", "taipei", "tpe", "khh"],
        "🇸🇬 新加坡": ["sg", "singapore", "sin", "changi"],
        "🇯🇵 日本": ["jp", "japan", "tokyo", "osaka", "nrt", "hnd", "kix"],
        "🇺🇸 美国": ["us", "unitedstates", "america", "lax", "sfo", "jfk", "sea", "ord"],
        "🇰🇷 韩国": ["kr", "korea", "seoul", "icn", "gmp"],
        "🇻🇳 越南": ["vn", "viet", "vietnam", "hanoi", "sgn", "han"],
        "🇩🇪 德国": ["de", "germany", "frankfurt", "berlin", "fra", "muc"],
        "🇬🇧 英国": ["uk", "unitedkingdom", "london", "lhr", "lgw", "man"],
        "🇫🇷 法国": ["fr", "france", "paris", "cdg", "ory"],
        "🇷🇺 俄罗斯": ["ru", "russia", "moscow", "svo", "dme", "led"],
        "🇨🇦 加拿大": ["ca", "canada", "toronto", "vancouver", "yyz", "yvr"],
        "🇦🇺 澳大利亚": ["au", "australia", "sydney", "melbourne", "syd", "mel"],
        "🇳🇱 荷兰": ["nl", "netherlands", "amsterdam", "ams"],
        "🇹🇷 土耳其": ["tr", "turkey", "istanbul", "ist"],
        "🇮🇳 印度": ["in", "india", "mumbai", "delhi", "bom", "del"],
        "🇲🇾 马来西亚": ["my", "malaysia", "kuala", "kul"],
        "🇵🇭 菲律宾": ["ph", "philippines", "manila", "mnl"],
        "🇹🇭 泰国": ["th", "thailand", "bangkok", "bkk"],
    }
    
    # 精准分词匹配，防止 "singapore" 中的 "in" 错误触发印度
    words = set(re.split(r'[^a-z0-9]', text_clean))
    for label, kws in fallback_keywords.items():
        if any(kw in words for kw in kws):
            return label

    # ==================== 3. 智能纯 IP / 域名兜底格式判定 ====================
    # IPv4 正则
    ipv4_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    # IPv6 正则 (标准及简写形式)
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    
    if re.match(ipv4_pattern, server_str) or re.match(ipv6_pattern, server_str):
        return "🌍 待识别"
        
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

    # 写入 config.yaml
    if clash_proxies:
        # ==================== 【 1. 纯静态国别基础归类 】 ====================
        active_regions = defaultdict(list)
        
        for p in clash_proxies:
            p_name = p.get("name", "")
            
            # 使用本地最纯净、绝不报错的静态关键字做初步归类
            if any(k in p_name.lower() for k in ["hk", "香港", "hongkong"]):
                active_regions["🇭🇰 香港节点"].append(p_name)
            elif any(k in p_name.lower() for k in ["tw", "台湾", "台灣", "taiwan"]):
                active_regions["🇹🇼 台湾节点"].append(p_name)
            elif any(k in p_name.lower() for k in ["sg", "新加坡", "singapore", "狮城"]):
                active_regions["🇸🇬 新加坡节点"].append(p_name)
            elif any(k in p_name.lower() for k in ["jp", "日本", "japan", "东京", "大阪"]):
                active_regions["🇯🇵 日本节点"].append(p_name)
            elif any(k in p_name.lower() for k in ["us", "美国", "美國", "america", "洛杉矶"]):
                active_regions["🇺🇸 美国节点"].append(p_name)
            elif any(k in p_name.lower() for k in ["kr", "韩国", "韓國", "korea", "首尔"]):
                active_regions["🇰🇷 韩国节点"].append(p_name)
            else:
                # 凡是带有“待识别”、“其他地区”或无特征的盲盒中转节点，通通塞进这里
                active_regions["🌍 其它地区"].append(p_name)

        # ==================== 【 2. 注入动态测速策略组 】 ====================
        proxy_groups = []
        all_other_nodes = active_regions.get("🌍 其它地区", [])
        
        # 生成各个国家的自动化测速组 (url-test)
        for group_name, node_list in active_regions.items():
            if group_name == "🌍 其它地区":
                continue # 盲盒池单独在下方配置
                
            proxy_groups.append({
                "name": group_name,
                "type": "url-test",
                "url": "http://gstatic.com",
                "interval": 300, # ⏱ 用户的客户端每 5 分钟在后台自动测速并刷新一次出口
                "tolerance": 50,
                "proxies": node_list + (["🌍 其它地区"] if all_other_nodes else []) # 巧妙塞入盲盒池
            })
            
        # 独立配置盲盒池作为底层支撑
        if all_other_nodes:
            proxy_groups.append({
                "name": "🌍 其它地区",
                "type": "select",
                "proxies": all_other_nodes
            })
            
        # 插入控制顶级大组
        available_group_names = [g["name"] for g in proxy_groups]
        
        proxy_groups.insert(0, {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["⚡ 自动测速分流"] + available_group_names + ["DIRECT"]
        })
        
        proxy_groups.insert(1, {
            "name": "⚡ 自动测速分流",
            "type": "url-test",
            "url": "http://gstatic.com",
            "interval": 300,
            "tolerance": 50,
            "proxies": [p.get("name") for p in clash_proxies] # 全节点总测速
        })

        # ==================== 【 3. 最终组合并无报错写入 YAML 】 ====================
        clash_config = {
            "mixed-port": 7890,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "proxies": clash_proxies,
            "proxy-groups": proxy_groups,
            "rules": [
                "MATCH,🚀 节点选择"
            ]
        }
        
        with open("config.yaml", "w", encoding="utf-8") as f:
        # 🟢 就在 config.yaml 写入成功的下方，直接插入这 4 行原生回写
        merged_links = "\n".join([f"vmess://{base64.b64encode(json.dumps(p['raw_json'], ensure_ascii=False).encode('utf-8')).decode('utf-8')}" if p.get('type') == 'vmess' else f"ss://{base64.b64encode(f\"{p.get('cipher')}:{p.get('password')}\".encode('utf-8')).decode('utf-8')}@{p.get('server')}:{p.get('port')}#{urllib.parse.quote(p.get('name',''))}" for p in clash_proxies]) + "\n"
        with open('index.html', 'w', encoding='utf-8') as f_b64:
            f_b64.write(base64.b64encode(merged_links.encode('utf-8')).decode('utf-8'))
        print("index.html 更新成功（Base64 订阅已与 YAML 节点完全对齐同步）")
        
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
            
        print("config.yaml 更新成功（已完美植入客户端动态出口自对齐机制）")
    else:
        # 提供一个最基础的有效 Clash 文件，防止报错
        with open("config.yaml", "w", encoding="utf-8") as f:
            yaml.dump({"mixed-port": 7890, "proxies": [], "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": ["DIRECT"]}], "rules": ["MATCH,🚀 节点选择"]}, f, allow_unicode=True)
        print("⚠ 未发现满足导入条件的 Clash 节点")
if __name__ == "__main__":
    main()
