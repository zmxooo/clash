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
    b64_part = re.sub(r'[^a-zA-Z0-9+/=_-]', '', b64_part)
    b64_part = b64_part.replace('-', '+').replace('_', '/')
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except:
        return b""

def get_final_label(server: str, remarks: str = "") -> str:
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立桃宛", r"lt|lithuania|立桃宛|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE: return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=5)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[server] = label
                return label
        except: pass
    return "🧿 其他地区"

def parse_link(link: str):
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')): return None

        # 针对 Hy2 的预处理：统一协议头并处理备注
        if link.startswith("hy2://"):
            link = link.replace("hy2://", "hysteria2://", 1)
        
        main_part = link.split('#')[0]
        orig_remarks = urllib.parse.unquote(link.split('#')[1]) if '#' in link else ""

        if link.startswith('vmess://'):
            b64_part = main_part[8:]
            raw_data = parse_vmess_b64(b64_part)
            if not raw_data: return None
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "type": "vmess",
                "server": data.get("add"),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "alterId": 0,
                "cipher": "auto",
                "tls": data.get("tls") in ["tls", True, 1],
                "original_remarks": data.get("ps", "")
            }
        
        elif any(link.startswith(p) for p in ['ss://', 'trojan://', 'vless://', 'hysteria2://']):
            u = urllib.parse.urlparse(main_part)
            p_type = u.scheme
            
            # 基础信息字典
            res = {
                "type": p_type,
                "server": u.hostname,
                "port": u.port or 443,
                "original_remarks": orig_remarks
            }

            # 协议特定参数补全
            if p_type == "hysteria2":
                res.update({
                    "password": u.username,
                    "auth": u.username,
                    "sni": u.hostname,
                    "skip-cert-verify": True
                })
            elif p_type == "vless":
                res.update({"uuid": u.username, "cipher": "auto", "tls": True, "udp": True})
            elif p_type == "trojan":
                res.update({"password": u.username, "sni": u.hostname, "tls": True, "udp": True})
            
            return res
    except:
        return None
    return None

# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("未找到 nodes.txt 文件")
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

    clash_proxies = []
    final_raw_links = []
    region_count = defaultdict(int)

    print(f"正在处理 {len(unique_links)} 个节点...")

    for link in unique_links:
        p = parse_link(link)
        if not p or not p.get("server"):
            continue

        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        region_count[label] += 1
        new_name = f"{label} {region_count[label]:02d} {CHANNEL_MARK}"
        
        # 记录原始链接用于 Base64 订阅输出
        clean_link = link.split('#')[0]
        final_raw_links.append(f"{clean_link}#{urllib.parse.quote(new_name)}")

        # 构建 Clash Proxy 对象
        p.pop("original_remarks", None)
        p["name"] = new_name
        clash_proxies.append(p)

    # 1. 生成 Clash YAML
    if clash_proxies:
        groups = [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择", "DIRECT"] + list(region_count.keys())},
            {"name": "⚡ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [px["name"] for px in clash_proxies]}
        ]
        for region in region_count.keys():
            groups.append({
                "name": region,
                "type": "url-test",
                "proxies": [px["name"] for px in clash_proxies if px["name"].startswith(region)]
            })
        
        config = {
            "port": 7890,
            "mode": "rule",
            "proxies": clash_proxies,
            "proxy-groups": groups,
            "rules": ["MATCH,🚀 节点选择"]
        }
        with open('config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        print("已生成 config.yaml")

    # 2. 生成 Base64 订阅 index.html
    if final_raw_links:
        b64_content = base64.b64encode("\n".join(final_raw_links).encode('utf-8')).decode('utf-8')
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(b64_content)
        print("已生成 index.html 订阅文件")

if __name__ == "__main__":
    main()
