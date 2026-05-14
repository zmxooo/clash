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
            # 💡 保持原有拼接，未对该无关语法做任何变动
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
            
            # 💡 严格贴回第二份脚本原本的统一返回格式，包含 label 键
            return {
                "label": get_final_label(data.get("add"), data.get("ps")),
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

            # Clash 配置
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
            # 💡 承接断开位置进行纯粹复制拼接
            clean_url = link.split('#')[0]
            rocket_links.append(f"{clean_url}#{urllib.parse.quote(new_name)}")

            # 处理 Clash 配置
            p['name'] = new_name
            
            if p.get('type') in ["ss", "trojan", "vless", "hysteria2"]:
                u = urllib.parse.urlparse(p.pop('link'))
                queries = dict(urllib.parse.parse_qsl(u.query))
                
                p['server'] = u.hostname
                p['port'] = int(u.port) if u.port else 443
                
                if p['type'] == "ss":
                    p['password'] = u.password if u.password else ""
                    p['cipher'] = u.username if u.username else "aes-256-gcm"
                elif p['type'] == "trojan":
                    p['password'] = u.username if u.username else ""
                    p['sni'] = queries.get("sni", u.hostname)
                    p['skip-cert-verify'] = True
                elif p['type'] == "vless":
                    p['uuid'] = u.username if u.username else ""
                    p['cipher'] = "auto"
                    p['tls'] = True if (queries.get("security") == "tls" or "tls" in link) else False
                    p['network'] = queries.get("type", "tcp")
                    if p['network'] == "ws":
                        p['ws-opts'] = {"path": queries.get("path", "/"), "headers": {"Host": queries.get("host", "")}}
                elif p['type'] == "hysteria2":
                    p['auth'] = u.username if u.username else ""
                    p['sni'] = queries.get("sni", u.hostname)
                    p['skip-cert-verify'] = True

            clash_proxies.append(p)

        region_map[label].append(new_name)

    # ==================== 导出 ====================
    if rocket_links:
        sub_content = "\n".join(rocket_links)
        sub_b64 = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

        with open('sub.txt', 'w', encoding='utf-8') as f:
            f.write(sub_b64)
        print(f"✅ 订阅文件已生成: sub.txt ({len(rocket_links)} 个节点)")

        # Clash 配置
        clash_config = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": [px["name"] for px in clash_proxies]
                }
            ],
            "rules": []
        }

        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        print("✅ Clash 配置文件已生成: clash.yaml")

    # 统计
    print("\n📊 地区统计:")
    for region, nodes in sorted(region_map.items(), key=lambda x: len(x), reverse=True):
        print(f"   {region} → {len(nodes)} 个")


if __name__ == "__main__":
    main()
