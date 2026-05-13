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
            clean = link.split('#')[0]
            rocket_links.append(f"{clean}#{urllib.parse.quote(new_name)}")

        region_map[label].append(new_name)

    # ====================== 优化后的策略组 ======================
    proxy_groups = []
    all_for_auto = []

    # 高优先级地区
    high_priority = ["🇭🇰 香港", "🇹🇼 台湾", "🇯🇵 日本", "🇸🇬 新加坡",
                     "🇺🇸 美国", "🇬🇧 英国", "🇰🇷 韩国", "🇩🇪 德国"]

    for region in high_priority:
        if region in region_map and region_map[region]:
            nodes = region_map[region]
            proxy_groups.append({"name": f"🌏 {region}", "type": "select", "proxies": nodes})
            all_for_auto.extend(nodes)

    # 中低优先级地区（按数量排序）
    other_regions = {k: v for k, v in region_map.items() if k not in high_priority}
    sorted_others = sorted(other_regions.items(), key=lambda x: len(x[1]), reverse=True)

    for label, nodes in sorted_others[:6]:
        if nodes:
            proxy_groups.append({"name": f"🌍 {label}", "type": "select", "proxies": nodes})
            all_for_auto.extend(nodes)

    # 剩余节点合并
    remaining = []
    for _, nodes in sorted_others[6:]:
        remaining.extend(nodes)
    if remaining:
        proxy_groups.append({"name": "🌐 其他节点", "type": "select", "proxies": remaining})
        all_for_auto.extend(remaining)

    # 核心策略组
    proxy_groups.extend([
        {"name": "♻️ 自动选择", "type": "url-test", "url": TEST_URL, "interval": 300,
         "tolerance": 60, "proxies": all_for_auto},
        {"name": "🚀 全局加速", "type": "select",
         "proxies": ["♻️ 自动选择", "DIRECT", "🌏 🇭🇰 香港"]},
        {"name": "📺 解锁流媒体", "type": "select",
         "proxies": ["🌏 🇺🇸 美国", "🌏 🇬🇧 英国", "🌏 🇯🇵 日本", "♻️ 自动选择"]},
        {"name": "🎮 游戏加速", "type": "select",
         "proxies": ["🌏 🇭🇰 香港", "🌏 🇯🇵 日本", "♻️ 自动选择"]},
    ])

    # ====================== 导出文件 ======================
    # 1. Shadowrocket 订阅
    if rocket_links:
        with open('rocket_sub.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(rocket_links))
        sub_b64 = base64.b64encode('\n'.join(rocket_links).encode()).decode()

    # 2. Clash 配置
    clash_config = {
        "mixed-port": 7890,
        "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": proxy_groups,
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 全局加速"
        ]
    }
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    # 3. 一键订阅网页
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>订阅 - {CHANNEL_MARK}</title>
<style>body{{font-family:system-ui;text-align:center;padding:60px;background:#0f0f0f;color:#0f0;}}
.btn{{display:inline-block;margin:12px;padding:16px 32px;background:#111;color:#0f0;
text-decoration:none;border:2px solid #0f0;border-radius:8px;font-size:18px;}}
.btn:hover{{background:#0f0;color:#000;}}</style></head><body>
<h1>节点订阅</h1>
<p>共 {len(rocket_links)} 个节点 | 更新时间: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<a href="data:text/plain;base64,{sub_b64}" class="btn" download="sub.txt">📥 下载订阅文件</a><br><br>
</body></html>"""
    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(html)

    # ====================== 统计信息 ======================
    print(f"\n🎉 处理完成！共 {len(rocket_links)} 个节点")
    print("地区分布：")
    for label, nodes in sorted(region_map.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"   {label}: {len(nodes)} 个")


if __name__ == "__main__":
    main()
