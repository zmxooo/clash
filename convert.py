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

# 严格适配 Mihomo/Clash 内核标准协议白名单
SUPPORTED_TYPES = ["vmess", "ss", "trojan", "vless", "hysteria2"]

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    """安全解码 Base64 字符串并自动补齐填充位"""
    b64_part = b64_part.strip()
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except:
        return b""

def get_final_label(server: str, remarks: str = "") -> str:
    """国家/地区识别：优先正则规则，其次调用开源 IP 库 API 纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

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

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
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
    """【防错升级】引入安全机制解包，对解析中发生的异常协议强制剔除"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        # 优先剥离备注别名
        parts = link.split('#', 1)
        raw_url = parts[0]
        raw_ps = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        if raw_url.startswith('vmess://'):
            b64_part = raw_url[8:]
            raw_data = parse_vmess_b64(b64_part)
            if not raw_data:
                return None
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "label": get_final_label(data.get("add"), data.get("ps")),
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }
            
        parsed = urllib.parse.urlparse(raw_url)
        proto = parsed.scheme.lower()
        if proto == 'hy2': 
            proto = 'hysteria2'
            
        if proto not in SUPPORTED_TYPES:
            return None

        # 提取更干净的主机名（过滤自带的端口干扰）
        hostname = parsed.hostname or parsed.netloc.split('@')[-1].split(':')[0]
        return {
            "label": get_final_label(hostname, raw_ps),
            "type": proto, 
            "link": link
        }
    except:
        return None

def clean_clash_proxy(p, new_name):
    """【类型防错锁】强制所有端口转型为 int，重构安全型 SS 双轨解析层"""
    if not p or p.get("type") not in SUPPORTED_TYPES:
        return None

    try:
        if p["type"] == "vmess":
            data = p["raw_data"]
            return {
                "name": new_name,
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)), # 强锁整型
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": data.get("net", "tcp"),
                "udp": True
            }
        
        parts = p['link'].split('#', 1)
        raw_url = parts[0]
        parsed = urllib.parse.urlparse(raw_url)
        queries = dict(urllib.parse.parse_qsl(parsed.query))

        # 稳健提取端口，避免 null 的发生
        try:
            port_val = int(parsed.port) if parsed.port else int(parsed.netloc.split(':')[-1].split('?')[0])
        except:
            port_val = 443

        hostname = parsed.hostname or parsed.netloc.split('@')[-1].split(':')[0]

        item = {
            "name": new_name,
            "type": p["type"],
            "server": hostname,
            "port": port_val,
            "udp": True
        }

        if p['type'] == "ss":
            if parsed.username and parsed.password:
                item.update({"cipher": parsed.username, "password": parsed.password})
            else:
                # 触发高级 SS 模块防崩溃：解决 Base64 旧合并包解密
                userinfo_encoded = parsed.netloc.split('@')[0]
                try:
                    user_info = parse_vmess_b64(userinfo_encoded).decode('utf-8', 'ignore')
                    if ':' in user_info:
                        item["cipher"], item["password"] = user_info.split(':', 1)
                    else:
                        item.update({"cipher": "aes-256-gcm", "password": userinfo_encoded})
                except:
                    item.update({"cipher": "aes-256-gcm", "password": userinfo_encoded})
            
        elif p['type'] == "trojan":
            item.update({
                "password": parsed.username or parsed.netloc.split('@')[0],
                "sni": queries.get("sni", hostname),
                "skip-cert-verify": True
            })

        elif p['type'] == "vless":
            item.update({
                "uuid": parsed.username or parsed.netloc.split('@')[0],
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
                "password": parsed.username or parsed.netloc.split('@')[0],  
                "sni": queries.get("sni", hostname),
                "skip-cert-verify": True
            })
            
        if not item.get("server") or not item.get("type") or not item.get("port"):
            return None
            
        return item
    except:
        return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 核心致命错误：未能在当前工作路径下寻寻找源节点文件 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

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

    print(f"🔄 成功加载 {len(unique_links)} 条非重复链路，启动精细提纯清洗层...")

    for link in unique_links:
        p = parse_link(link)
        if not p:
            continue

        label = p.get('label', "🧿 其他地区")
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        if p["type"] == "vmess":
            data = p["raw_data"].copy()
            data['ps'] = new_name
            new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
            new_b64 = base64.b64encode(new_json).decode('utf-8')
            rocket_links.append(f"vmess://{new_b64}")
        else:
            clean_url = link.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

        clash_item = clean_clash_proxy(p, new_name)
        if clash_item is not None:  
            clash_proxies.append(clash_item)
            region_map[label].append(new_name)

    print("💾 正在执行物理文件的持久化覆写...")
    
    if rocket_links:
        try:
            with open('rocket_links.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(rocket_links))
            rocket_b64 = base64.b64encode('\n'.join(rocket_links).encode('utf-8')).decode('utf-8')
            with open('rocket_subscription.txt', 'w', encoding='utf-8') as f:
                f.write(rocket_b64)
            print("   -> [OK] 小火箭加密订阅文件导出完毕。")
        except Exception as e:
            print(f"   -> [ERR] 转换 Shadowrocket 文本失败: {e}")

    try:
        proxy_names = [p["name"] for p in clash_proxies]
        if not proxy_names:
            proxy_names = ["DIRECT"]
            
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
        
        groups = [main_select_group, auto_test_group]

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
            
        main_select_group["proxies"].extend(proxy_names)

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
        
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print("   -> [OK] 真实有效的标准核心 config.yaml 覆写成功。")
        
    except Exception as e:
        print(f"   -> [ERR] 序列化 Clash 语法树失败: {e}")

if __name__ == '__main__':
    main()
