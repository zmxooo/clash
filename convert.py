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
def safe_base64_decode(b64: str) -> bytes:
    """更健壮的Base64解码"""
    b64 = b64.strip().replace('-', '+').replace('_', '/')
    padding = (4 - len(b64) % 4) % 4
    b64 += '=' * padding
    return base64.b64decode(b64)


def get_final_label(server: str, remarks: str = "") -> str:
    """优先正则识别 → IP自动纠正"""
    text = urllib.parse.unquote(str(remarks)).lower()

    # 正则优先匹配
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

    # IP自动纠正（修正错误标注）
    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.35)
            resp = requests.get(f"http://ip-api.com{server}?lang=zh-CN", timeout=8)
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
            data = json.loads(safe_base64_decode(b64_part).decode('utf-8', errors='ignore'))
            return {
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }
        elif link.startswith(('ss://', 'trojan://')):
            u = urllib.parse.urlparse(link)
            return {
                "type": "other",
                "link": link,
                "server": u.hostname,
                "original_remarks": urllib.parse.unquote(u.fragment) if u.fragment else ""
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

    # 去重（按核心链接）
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

        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"

        if p["type"] == "vmess":
            data = p["raw_data"].copy()
            data['ps'] = new_name
            new_b64 = base64.b64encode(
                json.dumps(data, separators=(',', ':')).encode('utf-8')
            ).decode('utf-8')
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

        else:  # ss / trojan
            # 修复点：确保 clean 是字符串而非列表，防止 Base64 编码格式错误
            clean = link.split('#')[0]
            rocket_links.append(f"{clean}#{urllib.parse.quote(new_name)}")

        region_map[label].append(new_name)

    # ====================== 优化后的策略组 ======================
    proxy_groups = []
    high_priority = ["🇭🇰 香港", "🇹🇼 台湾", "🇯🇵 日本", "🇸🇬 新加坡", "🇺🇸 美国"]
    
    all_names = [p["name"] for p in clash_proxies]
    
    if all_names:
        # 优化：自动选择分组，优先挑选高优先级地区的节点
        auto_proxies = []
        for region_tag in high_priority:
            # 匹配包含对应 Emoji 或地名的节点
            auto_proxies.extend([n for n in all_names if region_tag in n])
        
        # 如果高优先级地区没节点，则使用全部节点
        if not auto_proxies:
            auto_proxies = all_names

        proxy_groups.append({
            "name": "🚀 自动选择",
            "type": "url-test",
            "proxies": auto_proxies,
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 50
        })

        # 地区分组
        for label, names in region_map.items():
            proxy_groups.append({
                "name": f"📽️ {label}",
                "type": "select",
                "proxies": ["🚀 自动选择"] + names
            })

        # 总选择组
        proxy_groups.append({
            "name": "🔰 节点选择",
            "type": "select",
            "proxies": ["🚀 自动选择"] + [f"📽️ {l}" for l in region_map.keys()] + all_names
        })

    # ====================== 修复：Base64 导出 ======================
    try:
        # 修复点：将合并后的完整字符串进行 Base64 编码，确保导入配置正确
        sub_raw_text = "\n".join(rocket_links)
        sub_b64_content = base64.b64encode(sub_raw_text.encode('utf-8')).decode('utf-8')
        with open('subscribe.txt', 'w', encoding='utf-8') as f:
            f.write(sub_b64_content)
    except Exception as e:
        print(f"❌ 订阅文件导出失败: {e}")

    # ====================== 导出 Clash 配置 ======================
    clash_config = {
        "proxies": clash_proxies,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,🔰 节点选择"]
    }
    
    try:
        with open('clash_config.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        print(f"✅ 处理完成！已生成 subscribe.txt 和 clash_config.yaml")
    except Exception as e:
        print(f"❌ Clash 配置文件写入失败: {e}")

if __name__ == "__main__":
    main()
