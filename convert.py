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
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立陶宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷",
}

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    """标准的 Base64 填充与容错解码逻辑"""
    b64_part = b64_part.strip()
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except Exception:
        return b""

def get_final_label(server: str, remarks: str = "") -> str:
    """优先正则识别 → IP自动纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    # 正则优先匹配
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立桃宛|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    # IP自动纠正（核心修复：添加标准的 http:// 协议头及斜杠，防止崩序）
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=8)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country", "")
                emoji = "🌍"
                for k, v in EMOJI_MAP.items():
                    if k in country:
                        emoji = v
                        break
                label = f"{emoji} {country}"
                IP_CACHE[server] = label
                return label
        except Exception:
            pass
    return "🧿 其他地区"

def parse_link(link: str):
    """解析节点结构"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "label": get_final_label(data.get("add"), data.get("ps", "")),
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }
            
        elif link.startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            u = urllib.parse.urlparse(link)
            raw_ps = urllib.parse.unquote(u.fragment) if u.fragment else ""
            proto = link.split('://')[0].lower()
            if proto == 'hy2': 
                proto = 'hysteria2'
                
            return {
                "label": get_final_label(u.hostname, raw_ps),
                "type": proto, 
                "link": link
            }
    except Exception:
        return None
    return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

    seen = set()
    unique_links = []
    for line in lines:
        core = line.split('#')[0].strip()
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    print(f"🔄 正在处理 {len(unique_links)} 个去重节点...")

    for link in unique_links:
        p = parse_link(link)
        if not p:
            continue

        label = p.pop('label')
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        if p["type"] == "vmess":
            data = p["raw_data"].copy()
            data['ps'] = new_name
            new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
            new_b64 = base64.b64encode(new_json).decode('utf-8')
            rocket_links.append(f"vmess://{new_b64}")

            # Clash 配置 (增加高级网络参数回退保护)
            net_type = str(data.get("net", "tcp")).lower()
            vmess_node = {
                "name": new_name,
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": net_type,
            }
            if net_type == "ws":
                vmess_node["ws-opts"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}
            elif net_type == "grpc":
                vmess_node["grpc-opts"] = {"grpc-service-name": data.get("path", "")}
            clash_proxies.append(vmess_node)

        # 💡 完美承接并补全您截断的非 vmess 协议元数据解包逻辑
        else:
            clean_url = link.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")
            
            u = urllib.parse.urlparse(link)
            queries = dict(urllib.parse.parse_qsl(u.query))
            
            proxy_node = {
                "name": new_name,
                "type": p["type"],
                "server": u.hostname,
                "port": int(u.port) if u.port else 443
            }
            
            # 1. 适配 Shadowsocks (ss) 格式并防御式隔离修复 "cipher: auto" 问题
            if p["type"] == "ss":
                proxy_node["password"] = u.password if u.password else ""
                proxy_node["cipher"] = u.username if u.username else "aes-256-gcm"
                
                if not proxy_node["password"] and u.username:
                    try:
                        user_info = parse_vmess_b64(u.username).decode('utf-8', 'ignore')
                        if ':' in user_info:
                            proxy_node["cipher"], proxy_node["password"] = user_info.split(':', 1)
                    except Exception:
                        pass
                
                # 🔥 致命错误核心纠正防御线：ss 绝不能保留非法的 "auto" 或空作为加密方案
                current_cipher = str(proxy_node.get("cipher", "")).lower()
                if current_cipher in ["auto", "", "none"]:
                    proxy_node["cipher"] = "aes-256-gcm"
                        
            # 2. 适配 Trojan 格式
            elif p["type"] == "trojan":
                proxy_node["password"] = u.username if u.username else ""
                proxy_node["sni"] = queries.get("sni", u.hostname)
                proxy_node["skip-cert-verify"] = True
                
            # 3. 适配 VLESS 格式
            elif p["type"] == "vless":
                proxy_node["uuid"] = u.username if u.username else ""
                proxy_node["cipher"] = "auto"
                proxy_node["tls"] = queries.get("security") == "tls" or "tls" in link
                proxy_node["skip-cert-verify"] = True
                proxy_node["network"] = queries.get("type", "tcp")
                if proxy_node["network"] == "ws":
                    proxy_node["ws-opts"] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", "")}}
                elif proxy_node["network"] == "grpc":
                    proxy_node["grpc-opts"] = {"grpc-service-name": queries.get("serviceName", "")}
                    
            # 4. 适配 Hysteria2 (hy2) 格式
            elif p["type"] == "hysteria2":
                proxy_node["auth"] = u.username if u.username else ""
                proxy_node["sni"] = queries.get("sni", u.hostname)
                proxy_node["skip-cert-verify"] = True
                if queries.get("obfs"):
                    proxy_node["obfs"] = queries.get("obfs")
                    proxy_node["obfs-password"] = queries.get("obfs-password", "")

            clash_proxies.append(proxy_node)

        region_map[label].append(new_name)

    # ==================== 自动化持久文件写入 ====================
    # 导出 Shadowrocket 等客户端通用的 Base64 订阅文件
    if rocket_links:
        sub_raw = "\n".join(rocket_links)
        b64_output = base64.b64encode(sub_raw.encode('utf-8')).decode('utf-8')
        with open('subscribe.txt', 'w', encoding='utf-8') as f:
            f.write(b64_output)
        print("✅ 成功生成 64位基流通用订阅: subscribe.txt")

    # 导出移动客户端及本地 Clash 可直读的标准配置文件
    if clash_proxies:
        clash_yaml_structure = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "rule",
            "log-level": "info",
            "proxies": clash_proxies,
            "proxy-groups": [
                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": ["🗲 自动延迟测试"] + [p["name"] for p in clash_proxies]
                },
                {
                    "name": "🗲 自动延迟测试",
                    "type": "url-test",
                    "url": TEST_URL,
                    "interval": 300,
                    "tolerance": 50,
                    "proxies": [p["name"] for p in clash_proxies]
                }
            ],
            "rules": [
                "MATCH,🚀 节点选择"
            ]
        }
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_yaml_structure, f, allow_unicode=True, sort_keys=False)
        print("✅ 成功生成合规 Clash 配置文件: config.yaml")

if __name__ == "__main__":
    main()
