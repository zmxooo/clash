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
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    return base64.b64decode(b64_part)


def get_final_label(server: str, remarks: str = "") -> str:
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.3)
            resp = requests.get(f"http://ip-api.com/json/{server}?lang=zh-CN", timeout=8)
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
    try:
        link = link.strip()
        if not link or link.startswith(('import', 'def', '#', 'git')):
            return None

        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "port": data.get("port"),
                "original_remarks": data.get("ps", "")
            }

        # 支持 vless、ss、trojan、clw 等
        elif any(link.startswith(p) for p in ['vless://', 'ss://', 'trojan://', 'hysteria2://', 'tuic://', 'clw://']):
            if '#' in link:
                main_part, fragment = link.split('#', 1)
                remarks = urllib.parse.unquote(fragment)
            else:
                main_part = link
                remarks = ""

            u = urllib.parse.urlparse(main_part)
            server = u.hostname
            port = u.port

            # vless 特殊格式处理
            if not server and '@' in u.path:
                auth_part = u.path.lstrip('/')
                if '@' in auth_part:
                    _, server_port = auth_part.split('@', 1)
                    if ':' in server_port:
                        server = server_port.split(':')[0]
                        port = int(server_port.split(':')[1].split('?')[0])

            return {
                "type": "other",
                "link": link,
                "server": server,
                "port": port,
                "original_remarks": remarks
            }
        return None
    except:
        return None


# ==================== 主程序 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 未找到 nodes.txt 文件")
        return

    with open('nodes.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

    # ==================== 恢复最初的简单去重 ====================
    seen = set()
    unique_links = []
    for line in lines:
        core = line.split('#')[0]          # 只取 # 前的部分
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    print(f"🔄 原始节点 {len(lines)} 个 → 去重后 {len(unique_links)} 个")

    # ==================== 处理节点 ====================
    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    for link in unique_links:
        p = parse_link(link)
        if not p:
            continue

        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        new_name = f"{label} {len(region_map[label]) + 1:02d} {CHANNEL_MARK}"

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
            # vless、ss、trojan、clw 等
            clean = link.split('#')[0]
            rocket_links.append(f"{clean}#{urllib.parse.quote(new_name)}")

        region_map[label].append(new_name)

    # ==================== 导出 ====================
    if not rocket_links:
        print("⚠️ 没有有效节点")
        return

    sub_content = "\n".join(rocket_links)
    sub_b64 = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

    with open('sub.txt', 'w', encoding='utf-8') as f:
        f.write(sub_b64)

    # Clash 配置
    all_proxies = [p["name"] for p in clash_proxies]
    proxy_groups = [
        {"name": "🚀 全局选择", "type": "select", "proxies": all_proxies},
        {"name": "🌐 香港", "type": "url-test", "proxies": region_map.get("🇭🇰 香港", []), "url": TEST_URL, "interval": 300},
        {"name": "🌐 美国", "type": "url-test", "proxies": region_map.get("🇺🇸 美国", []), "url": TEST_URL, "interval": 300},
        {"name": "🌐 其他", "type": "url-test", "proxies": region_map.get("🧿 其他地区", []), "url": TEST_URL, "interval": 300},
    ]

    clash_config = {
        "mixed-port": 7890,
        "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": proxy_groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 全局选择"]
    }

    with open('clash.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    print(f"\n🎉 处理完成！最终生成 {len(rocket_links)} 个节点")
    print("   sub.txt  (订阅链接)")
    print("   clash.yaml (配置)")


if __name__ == "__main__":
    main()
