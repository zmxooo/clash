import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# ==================== 配置 ====================
IP_CACHE = {}

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "德国": "🇩🇪", "立陶宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷",
}

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    """安全解码 Base64 字符串并自动补齐填充位"""
    b64_part = b64_part.strip()
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    return base64.b64decode(b64_part)

def get_final_label(server: str, remarks: str = "") -> str:
    """国家/地区识别：优先正则规则，其次调用开源 IP 库 API 纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    # 正则规则库
    meta = [
        ("香港", r"hk|hongkong|香港|🇨🇳"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美|🇺🇸"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國|首尔"), ("日本", r"jp|japan|日本|东京|大阪"),
        ("新加坡", r"sg|singapore|新加坡|狮城"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立桃宛|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # IP 纯数字检测与国家自动反查
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)  # 严格遵守 ip-api 限流频率
            resp = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=5)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = ""
                for k in EMOJI_MAP.keys():
                    if k in country:
                        label = f"{EMOJI_MAP[k]} {k}"
                        break
                if not label:
                    label = f"🌍 {country}"
                IP_CACHE[server] = label
                return label
        except:
            pass
    return "🧿 其他地区"

def parse_link(link: str):
    """【真机修复】提取各种底层标准链路的核心属性字典，彻底修复列表切片丢失索引隐患"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        if link.startswith('vmess://'):
            parts = link[8:].split('#')
            b64_part = parts[0]
            raw_data = parse_vmess_b64(b64_part)
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "label": get_final_label(data.get("add"), data.get("ps")),
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }
            
        elif link.startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            parts = link.split('#')
            main_part = parts[0]
            raw_ps = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
            
            proto = main_part.split('://')[0].lower()
            if proto == 'hy2': 
                proto = 'hysteria2'
                
            netloc_part = main_part.split('://')[1] if '://' in main_part else main_part
            netloc = netloc_part.split('/')[0].split('?')[0]
            
            if '@' in netloc:
                server_host = netloc.split('@')[1].split(':')[0]
            else:
                server_host = netloc.split(':')[0]
                
            return {
                "label": get_final_label(server_host, raw_ps),
                "type": proto, 
                "link": link
            }
    except:
        return None

def clean_clash_proxy(p, new_name):
    """【真机修复】清洗节点数据，严格安全解包多段式字符串，格式化输出符合各协议标准的组件"""
    try:
        if p["type"] == "vmess":
            data = p["raw_data"]
            return {
                "name": new_name,
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": data.get("net", "tcp"),
                "udp": True
            }
        
        parts = p['link'].split('#')
        main_part = parts[0]
        netloc_part = main_part.split('://')[1] if '://' in main_part else main_part
        netloc = netloc_part.split('/')[0].split('?')[0]
        
        if '@' in netloc:
            server = netloc.split('@')[1].split(':')[0]
            auth_str = netloc.split('@')[0]
        else:
            server = netloc.split(':')[0]
            auth_str = ""
            
        port_part = netloc.split('@')[-1]
        port = int(port_part.split(':')[1]) if ':' in port_part else 443
        queries = dict(urllib.parse.parse_qsl(main_part.split('?')[1])) if '?' in main_part else {}

        item = {
            "name": new_name,
            "type": p["type"],
            "server": server,
            "port": port,
            "udp": True
        }

        if p['type'] == "ss":
            cipher = auth_str.split(':')[0] if auth_str else "aes-256-gcm"
            password = auth_str.split(':')[1] if ':' in auth_str else ""
            if not password and cipher:
                try:
                    user_info = parse_vmess_b64(cipher).decode('utf-8', 'ignore')
                    if ':' in user_info:
                        cipher, password = user_info.split(':', 1)
                except:
                    pass
            item.update({"cipher": cipher, "password": password})

        elif p['type'] == "trojan":
            item.update({
                "password": auth_str,
                "sni": queries.get("sni", server),
                "skip-cert-verify": True
            })

        elif p['type'] == "vless":
            item.update({
                "uuid": auth_str,
                "cipher": "auto",
                "tls": True if (queries.get("security") == "tls" or "tls" in p['link']) else False,
                "network": queries.get("type", "tcp")
            })
            if queries.get("sni"):
                item["servername"] = queries.get("sni")
            if item['network'] == "ws":
                item['ws-opts'] = {
                    "path": queries.get("path", "/"), 
                    "headers": {"Host": queries.get("host", "")}
                }

        elif p['type'] == "hysteria2":
            item.update({
                "password": auth_str,  
                "sni": queries.get("sni", server),
                "skip-cert-verify": True
            })
            
        return item
    except:
        return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 核心致命错误：未能在当前工作路径下寻找到源节点集文件 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

    # 深度链接去重
    seen = set()
    unique_links = []
    for line in lines:
        core = line.split('#')[0]
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    print(f"🔄 捕获到唯一非空链路共 {len(unique_links)} 条。开始解析...")

    for link in unique_links:
        p = parse_link(link)
        if not p:
            continue

        label = p.get('label')
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        # 1. 组装 Shadowrocket 明文列表
        if p["type"] == "vmess":
            data = p["raw_data"].copy()
            data['ps'] = new_name
            new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
            new_b64 = base64.b64encode(new_json).decode('utf-8')
            rocket_links.append(f"vmess://{new_b64}")
        else:
            clean_url = link.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

        # 2. 组装并过滤 Clash 代理列表
        clash_item = clean_clash_proxy(p, new_name)
        if clash_item:
            clash_proxies.append(clash_item)
            region_map[label].append(new_name)

    print("💾 正在持久化输出各客户端配置文件...")
    
    # ============ 格式持久化 1：Shadowrocket 订阅文件 ============
    if rocket_links:
        try:
            with open('rocket_links.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(rocket_links))
            
            rocket_b64 = base64.b64encode('\n'.join(rocket_links).encode('utf-8')).decode('utf-8')
            with open('rocket_subscription.txt', 'w', encoding='utf-8') as f:
                f.write(rocket_b64)
            print("   -> [OK] 基础格式明文集及小火箭 Base64 订阅双规格导出成功。")
        except Exception as e:
            print(f"   -> [ERR] 转换 Shadowrocket 文本失败: {e}")

    # ============ 格式持久化 2：Clash (Mihomo) YAML 分组逻辑 ============
    try:
        proxy_names = [p["name"] for p in clash_proxies]
        
        # 极端空情况容错
        if not proxy_names:
            proxy_names = ["DIRECT"]
            
        # 初始化标准顶层代理组
        main_select_group = {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["📌 自动选择", "DIRECT"]
        }
        
        auto_test_group = {
            "name": "📌 自动选择",
            "type": "url-test",
            "proxies": proxy_names,
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 50
        }
        
        # 实例化分组容器
        groups = [main_select_group, auto_test_group]

        # 动态创建细化的“国家/地域细分策略分组”
        for region, nodes in region_map.items():
            if not nodes:
                continue
            main_select_group["proxies"].append(region)
            
            groups.append({
                "name": region,
                "type": "url-test",
                "proxies": nodes,
                "url": TEST_URL,
                "interval": 300,
                "tolerance": 50
            })
            
        # 追加底层的全量原始节点作为手动选择项
        main_select_group["proxies"].extend(proxy_names)

        # 构建完整的全局 YAML 树形结构
        clash_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "Rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": clash_proxies,
            "proxy-groups": groups,
            "rules": [
                "DOMAIN-SUFFIX,google.com,🚀 节点选择",
                "GEOIP,LAN,DIRECT,no-resolve",
                "GEOIP,CN,DIRECT",
                "MATCH,🚀 节点选择"
            ]
        }
        
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print("   -> [OK] 包含跨组依赖与分流地域树的完整 clash_config.yaml 生成完毕。")
        
    except Exception as e:
        print(f"   -> [ERR] 序列化 Clash 语法树失败: {e}")

if __name__ == '__main__':
    main()
