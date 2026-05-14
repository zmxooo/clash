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
    """采用第一份代码中的 Base64 填充与解码逻辑"""
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    return base64.b64decode(b64_part)

def get_final_label(server: str, remarks: str = "") -> str:
    """优先正则识别 → IP自动纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    # 正则优先匹配
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

    # IP自动纠正
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            # 💡 修复点：原代码缺少 http:// 及 / 导致请求失败，此处已修正
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
    """解析节点"""
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
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
            main_part = link.split('#')[0]
            raw_ps = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""
            
            proto = main_part.split('://')[0].lower()
            if proto == 'hy2': 
                proto = 'hysteria2'
                
            server_host = ""
            netloc = main_part.split('://')[1].split('/')[0].split('?')[0]
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

    print("🔄 正在处理节点...")

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

            clash_proxies.append({
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
            })

        else:
            clean_url = link.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

            p['name'] = new_name
            
            if p.get('type') in ["ss", "trojan", "vless", "hysteria2"]:
                main_part = p['link'].split('#')[0]
                netloc = main_part.split('://')[1].split('/')[0].split('?')[0]
                
                if '@' in netloc:
                    p['server'] = netloc.split('@')[1].split(':')[0]
                    auth_str = netloc.split('@')[0]
                else:
                    p['server'] = netloc.split(':')[0]
                    auth_str = ""
                    
                if ':' in netloc.split('@')[-1]:
                    p['port'] = int(netloc.split('@')[-1].split(':')[1])
                else:
                    p['port'] = 443
                    
                queries = {}
                if '?' in main_part:
                    queries = dict(urllib.parse.parse_qsl(main_part.split('?')[1]))
                
                if p['type'] == "ss":
                    p['password'] = auth_str.split(':')[1] if ':' in auth_str else ""
                    p['cipher'] = auth_str.split(':')[0] if auth_str else "aes-256-gcm"
                    if not p['password'] and p['cipher']:
                        try:
                            user_info = parse_vmess_b64(p['cipher']).decode('utf-8', 'ignore')
                            if ':' in user_info:
                                p['cipher'], p['password'] = user_info.split(':', 1)
                        except:
                            pass
                elif p['type'] == "trojan":
                    p['password'] = auth_str
                    p['sni'] = queries.get("sni", p['server'])
                    p['skip-cert-verify'] = True
                elif p['type'] == "vless":
                    p['uuid'] = auth_str
                    p['cipher'] = "auto"
                    p['tls'] = True if (queries.get("security") == "tls" or "tls" in p['link']) else False
                    p['network'] = queries.get("type", "tcp")
                    if p['network'] == "ws":
                        p['ws-opts'] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", "")}}
                elif p['type'] == "hysteria2":
                    p['auth'] = auth_str
                    p['sni'] = queries.get("sni", p['server'])
                    p['skip-cert-verify'] = True

                if 'link' in p: p.pop('link')

            clash_proxies.append(p)

        region_map[label].append(new_name)

    # ============ 补全：持久化输出逻辑 ============
    
    # 1. 输出 Shadowrocket 订阅格式（通用明文行 / 或 Base64 订阅文件）
    try:
        # 写入明文链接
        with open('rocket_links.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(rocket_links))
        
        # 写入 Shadowrocket 标准 Base64 订阅
        rocket_b64 = base64.b64encode('\n'.join(rocket_links).encode('utf-8')).decode('utf-8')
        with open('rocket_subscription.txt', 'w', encoding='utf-8') as f:
            f.write(rocket_b64)
        print("✅ Shadowrocket 订阅生成成功 -> rocket_subscription.txt")
    except Exception as e:
        print(f"❌ 导出 Shadowrocket 订阅失败: {e}")

    # 2. 输出 Clash 配置文件
    try:
        # 获取所有生成的新节点名称列表，用于代理组
        all_proxy_names = [p['name'] for p in clash_proxies]
        
        if all_proxy_names:
            clash_config = {
                "port": 7890,
                "socks-port": 7891,
                "allow-lan": True,
                "mode": "Rule",
                "log-level": "info",
                "external-controller": "127.0.0.1:9090",
                "proxies": clash_proxies,
                "proxy-groups": [
                    {
                        "name": "🚀 节点选择",
                        "type": "select",
                        "proxies": ["📌 自动选择", "🔮 直连"] + all_proxy_names
                    },
                    {
                        "name": "📌 自动选择",
                        "type": "url-test",
                        "url": TEST_URL,
                        "interval": 300,
                        "tolerance": 50,
                        "proxies": all_proxy_names
                    },
                    {
                        "name": "🔮 直连",
                        "type": "select",
                        "proxies": ["DIRECT"]
                    }
                ],
                "rules": [
                    "MATCH,🚀 节点选择"
                ]
            }
            
            # 使用 safe_dump 生成标准的 YAML 配置，确保中文不乱码
            with open('clash_config.yaml', 'w', encoding='utf-8') as f:
                yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)
            print("✅ Clash 配置文件生成成功 -> clash_config.yaml")
        else:
            print("⚠️ 未发现有效节点，未生成 Clash 配置。")
            
    except Exception as e:
        print(f"❌ 导出 Clash 配置文件失败: {e}")

    print(f"🎉 处理完成！共成功清洗并分流了 {len(clash_proxies)} 个独立节点。")

if __name__ == '__main__':
    main()
