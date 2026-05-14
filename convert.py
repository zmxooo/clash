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
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立桃宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷",
}

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    return base64.b64decode(b64_part)

def get_final_label(server: str, remarks: str = "") -> str:
    """优先正则识别 → IP自动纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立桃宛", r"lt|lithuania|立桃宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=8)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[server] = label
                return label
        except:
            pass
    return "🧿 其他地区"

def parse_link(link: str):
    """一站式精准解析所有主流协议，直接输出标准 Clash 代理字典"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        # 1. 独立处理 VMess 协议
        if link.lower().startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            server_host = data.get("add")
            raw_ps = data.get("ps", "")
            
            return {
                "label": get_final_label(server_host, raw_ps),
                "type": "vmess",
                "server": server_host,
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                "skip-cert-verify": True,
                "network": data.get("net", "tcp"),
                "is_vmess_raw": True, # 打上标记方便 main 函数二次编码订阅链接
                "raw_data": data
            }
            
        # 2. 通用解析其他标准 URI 协议 (ss, trojan, vless, hy2)
        elif link.lower().startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            main_part = link.split('#')[0]
            raw_ps = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            proto = main_part.split('://')[0].lower()
            if proto == 'hy2': 
                proto = 'hysteria2'
                
            netloc = main_part.split('://')[1].split('/')[0].split('?')[0]
            auth_str = ""
            if '@' in netloc:
                auth_str = netloc.split('@')[0]
                server_part = netloc.split('@')[1]
            else:
                server_part = netloc
                
            server_host = server_part.split(':')[0]
            port = int(server_part.split(':')[1]) if ':' in server_part else 443
                
            queries = {}
            if '?' in main_part:
                queries = dict(urllib.parse.parse_qsl(main_part.split('?')[1]))
                
            result = {
                "label": get_final_label(server_host, raw_ps),
                "type": proto,
                "server": server_host,
                "port": port
            }

            # Hysteria 2 特征注入
            if proto == "hysteria2":
                result.update({
                    "auth": auth_str,
                    "sni": queries.get("sni", server_host),
                    "skip-cert-verify": True,
                    "up": queries.get("up", "100"),
                    "down": queries.get("down", "100")
                })
                if queries.get("obfs"):
                    result["obfs"] = queries.get("obfs")
                    result["obfs-password"] = queries.get("obfs-password", "")
                    
            # Shadowsocks 特征注入
            elif proto == "ss":
                result['password'] = auth_str.split(':')[1] if ':' in auth_str else ""
                result['cipher'] = auth_str.split(':')[0] if auth_str else "aes-256-gcm"
                if not result['password'] and result['cipher']:
                    try:
                        user_info = parse_vmess_b64(result['cipher']).decode('utf-8', 'ignore')
                        if ':' in user_info:
                            result['cipher'], result['password'] = user_info.split(':', 1)
                    except:
                        pass
                        
            # Trojan 特征注入
            elif proto == "trojan":
                result['password'] = auth_str
                result['sni'] = queries.get("sni", server_host)
                result['skip-cert-verify'] = True
                
            # VLESS 特征注入
            elif proto == "vless":
                result['uuid'] = auth_str
                result['cipher'] = "auto"
                result['tls'] = True if (queries.get("security") == "tls" or "tls" in link.lower()) else False
                result['network'] = queries.get("type", "tcp")
                if result['network'] == "ws":
                    result['ws-opts'] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", "")}}

            return result
    except Exception as e:
        print(f"❌ 解析单行节点失败: {e}")
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
        core = line.split('#')[0]
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    print(f"🔄 正在处理共 {len(unique_links)} 个去重节点...")

    for link in unique_links:
        p = parse_link(link)
        if not p:
            continue

        label = p.pop('label')
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        # 区分重组小火箭订阅链接的逻辑
        if p.get("is_vmess_raw"):
            p.pop("is_vmess_raw")
            data = p.pop("raw_data")
            data['ps'] = new_name
            new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
            new_b64 = base64.b64encode(new_json).decode('utf-8')
            rocket_links.append(f"vmess://{new_b64}")
        else:
            clean_url = link.split('#')[0]
            # 兼容非标的 hy2:// 统一输出标准小火箭命名
            if clean_url.startswith('hy2://'):
                clean_url = 'hysteria2://' + clean_url[6:]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

        # 统一注入标准名称并归档至 Clash 核心列表
        p['name'] = new_name
        clash_proxies.append(p)
        region_map[label].append(new_name)

    # ==================== 持久化数据落地 ====================
    if not clash_proxies:
        print("❌ 未成功解析出任何有效代理节点。")
        return

    # 1. 导出小火箭订阅文本
    try:
        with open('rocket_links.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(rocket_links))
        rocket_b64 = base64.b64encode('\n'.join(rocket_links).encode('utf-8')).decode('utf-8')
        with open('rocket_subscription.txt', 'w', encoding='utf-8') as f:
            f.write(rocket_b64)
        print("✅ 成功生成 Shadowrocket 订阅 -> rocket_subscription.txt")
    except Exception as e:
        print(f"❌ 导出小火箭订阅失败: {e}")

    # 2. 导出 Clash (Mihomo) YAML 配置
    try:
        all_proxy_names = [p['name'] for p in clash_proxies]
        clash_config = {
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "mode": "Rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": clash_proxies,
            "proxy-groups": [
                {"name": "🚀 节点选择", "type": "select", "proxies": ["📌 自动选择", "🔮 直连"] + all_proxy_names},
                {"name": "📌 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300, "tolerance": 50, "proxies": all_proxy_names},
                {"name": "🔮 直连", "type": "select", "proxies": ["DIRECT"]}
            ],
            "rules": ["MATCH,🚀 节点选择"]
        }
        
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)
        print("✅ 成功生成 Clash 配置文件 -> clash_config.yaml")
    except Exception as e:
        print(f"❌ 导出 Clash 配置文件失败: {e}")

    print(f"🎉 脚本运行成功，共顺利清洗、规范化和分类了 {len(clash_proxies)} 个主流协议节点！")

if __name__ == '__main__':
    main()
