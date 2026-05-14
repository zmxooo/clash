import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
import time
from collections import defaultdict

# ==================== 配置 ====================
CHANNEL_MARK = "@zmxooo"
IP_CACHE = {}

# ==================== 工具函数 ====================
def safe_b64decode(s):
    """安全解码 Base64，处理填充和特殊字符"""
    # 移除可能存在的协议头之后的非法字符
    s = re.sub(r'[^a-zA-Z0-9+/=_-]', '', s)
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', 'ignore')
    except:
        return ""

def get_final_label(server, remarks):
    """识别国家/地区并返回对应的 Emoji 标签"""
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("🇭🇰 香港", r"hk|hongkong|香港"), 
        ("🇹🇼 台湾", r"tw|taiwan|台灣|台湾"),
        ("🇺🇸 美国", r"us|unitedstates|美国|美國|usa"), 
        ("🇰🇷 韩国", r"kr|korea|韩国|韓國"),
        ("🇯🇵 日本", r"jp|japan|日本"), 
        ("🇸🇬 新加坡", r"sg|singapore|新加坡"),
        ("🇩🇪 德国", r"de|germany|德国"), 
        ("🇬🇧 英国", r"gb|uk|britain|英国"),
        ("🇷🇺 俄罗斯", r"ru|russia|俄罗斯"),
        ("🇻🇳 越南", r"vn|vietnam|越南"),
    ]
    
    # 1. 优先通过备注识别
    for label, pattern in meta:
        if re.search(pattern, text):
            return label

    # 2. 如果备注没写，且 server 是 IP，则查询 API
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE: return IP_CACHE[server]
        try:
            # 增加延迟防止被 API 封禁
            time.sleep(0.3)
            resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=2).json()
            if resp.get("status") == "success":
                country = resp.get("country")
                label = f"🌍 {country}"
                IP_CACHE[server] = label
                return label
        except:
            pass
    return "🧿 其他地区"

def parse_link(link):
    """全协议解析器，确保 VMess 和 Hy2 同时兼容"""
    try:
        link = link.strip()
        if not link: return None

        # --- VMess 解析 ---
        if link.startswith('vmess://'):
            # 截掉可能存在的备注部分 (#)
            b64_content = link[8:].split('#')[0].split('?')[0]
            raw_json = safe_b64decode(b64_content)
            if not raw_json: return None
            
            d = json.loads(raw_json)
            return {
                "label": get_final_label(d.get("add"), d.get("ps")),
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port", 443)),
                "uuid": d.get("id"),
                "alterId": int(d.get("aid", 0)),
                "cipher": "auto",
                "tls": True if str(d.get("tls")).lower() in ["tls", "1", "true"] else False,
                "network": d.get("net", "tcp"),
                "ws-opts": {"path": d.get("path"), "headers": {"Host": d.get("host", "")}} if d.get("net") == "ws" else None
            }

        # --- Hysteria 2 / Hy2 解析 ---
        elif link.startswith(('hysteria2://', 'hy2://')):
            u = urllib.parse.urlparse(link)
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "hysteria2",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username, # Hysteria 2 核心字段
                "sni": u.hostname,
                "skip-cert-verify": True,
                "alpn": ["h3"]
            }

        # --- Shadowsocks / Trojan / VLESS 解析 ---
        elif link.startswith(('ss://', 'trojan://', 'vless://')):
            u = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qs(u.query)
            node_type = u.scheme
            
            node = {
                "label": get_final_label(u.hostname, u.fragment),
                "type": node_type,
                "server": u.hostname,
                "port": u.port or 443,
                "skip-cert-verify": True,
                "sni": q.get("sni", [u.hostname])[0]
            }
            
            if node_type == "vless":
                node.update({"uuid": u.username, "cipher": "auto"})
            elif node_type == "ss":
                node.update({"password": u.username, "cipher": "auto"})
            else: # trojan
                node.update({"password": u.username})
            return node

    except Exception:
        return None
    return None

# ==================== 3. 主程序 ====================
def main():
    input_file = 'nodes.txt'
    output_file = 'config.yaml'

    if not os.path.exists(input_file):
        print(f"❌ 错误：未找到 {input_file}")
        return

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines()

    proxies = []
    region_count = defaultdict(int)

    print(f"🚀 开始处理 {len(lines)} 条链接...")

    for line in lines:
        p = parse_link(line)
        if p and p.get("server"):
            label = p.pop('label')
            region_count[label] += 1
            # 格式化名称：[国家Emoji] [编号] [频道标识]
            p['name'] = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"
            proxies.append(p)

    if not proxies:
        print("⚠️ 未识别到有效节点，请检查 nodes.txt 内容。")
        return

    # 构建 Clash 配置文件结构
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["⚡ 自动选择", "DIRECT"] + [px['name'] for px in proxies]
            },
            {
                "name": "⚡ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [px['name'] for px in proxies]
            }
        ],
        "rules": [
            "MATCH,🚀 节点选择"
        ]
    }

    # 写入 YAML 文件
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print("-" * 30)
    print(f"✅ 处理完成！")
    print(f"📦 总计节点: {len(proxies)}")
    print(f"📝 配置文件: {output_file}")
    print("-" * 30)

if __name__ == "__main__":
    main()
