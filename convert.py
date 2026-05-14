import base64
import json
import yaml
import urllib.parse
import os
import re
import requests
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"

# ==================== 工具函数 ====================
def safe_b64decode(s):
    """鲁棒的 Base64 解码，确保 VMess 链接不因格式微调而失效"""
    # 移除协议头后可能干扰解码的非 Base64 字符
    s = s.split('#')[0].split('?')[0] 
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
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("🇭🇰 香港", r"hk|hongkong|香港"), ("🇹🇼 台湾", r"tw|taiwan|台灣|台湾"),
        ("🇺🇸 美国", r"us|unitedstates|美国|美國"), ("🇰🇷 韩国", r"kr|korea|韩国|韓國"),
        ("🇯🇵 日本", r"jp|japan|日本"), ("🇸🇬 新加坡", r"sg|singapore|新加坡"),
    ]
    for label, pattern in meta:
        if re.search(pattern, text): return label
    return "🌍 其他地区"

# ==================== 全协议解析器 (Hy2 修复版) ====================
def parse_link(link):
    try:
        link = link.strip()
        if not link: return None

        # --- VMess 修复：增强解码稳定性 ---
        if link.startswith('vmess://'):
            raw_json = safe_b64decode(link[8:])
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
                "ws-opts": {"path": d.get("path")} if d.get("net") == "ws" else None
            }

        # --- Hysteria 2 (修复补丁) ---
        elif link.startswith(('hysteria2://', 'hy2://')):
            u = urllib.parse.urlparse(link)
            # 必须包含 password、sni、alpn 才能在 Clash 中显示并生效
            return {
                "label": get_final_label(u.hostname, u.fragment),
                "type": "hysteria2",
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username,
                "sni": u.hostname,
                "skip-cert-verify": True,
                "alpn": ["h3"]
            }

        # --- 其他协议 (SS/VLESS/Trojan) ---
        elif link.startswith(('ss://', 'vless://', 'trojan://')):
            u = urllib.parse.urlparse(link)
            node_type = u.scheme
            node = {
                "label": get_final_label(u.hostname, u.fragment),
                "type": node_type,
                "server": u.hostname,
                "port": u.port or 443,
                "password": u.username if node_type != "vless" else None,
                "uuid": u.username if node_type == "vless" else None,
                "cipher": "auto" if node_type != "trojan" else None,
                "tls": True,
                "skip-cert-verify": True
            }
            return node

    except:
        return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()

    proxies = []
    region_count = defaultdict(int)

    for line in lines:
        p = parse_link(line)
        if p:
            label = p.pop('label')
            region_count[label] += 1
            p['name'] = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"
            proxies.append(p)

    if not proxies:
        print("识别失败，请检查链接格式")
        return

    # 输出 Clash 配置
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [px['name'] for px in proxies], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🔰 全部节点", "type": "select", "proxies": [px['name'] for px in proxies]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print(f"✅ 处理完成！节点总数: {len(proxies)}")

if __name__ == "__main__":
    main()
