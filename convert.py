import base64, json, urllib.parse, os, re, requests, time, yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# ==================== 健壮的解析模块 ====================
def safe_decode(data):
    """防止 Base64 填充导致的脚本崩溃"""
    try:
        data = data.replace('-', '+').replace('_', '/')
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except: return ""

def parse_link(link):
    """
    针对 Screenshot_2026-05-14-14-37-00-39_c09219dfd10e7f2c59cb30cbda5bcba6.jpg 报错修复:
    1. SS: 严禁 cipher: auto，必须提取真实加密方式。
    2. VMESS: 补全 WS/TLS 传输层，确保 PC/移动端互通。
    """
    try:
        link = link.strip()
        if not link: return None

        # --- Shadowsocks (SS) 深度修复 ---
        if link.startswith('ss://'):
            main, remarks = link.split('#', 1) if '#' in link else (link, "")
            raw = main[5:]
            # 兼容处理: ss://base64(method:pass)@ip:port
            if "@" in raw:
                u_b64, s_part = raw.rsplit("@", 1)
                user_info = safe_decode(u_b64)
                method, password = user_info.split(':', 1)
                server, port = s_part.split(':', 1)
            else:
                # 兼容处理: ss://base64(method:pass@ip:port)
                decoded = safe_decode(raw)
                user_info, s_part = decoded.rsplit("@", 1)
                method, password = user_info.split(':', 1)
                server, port = s_part.split(':', 1)
            
            return {
                "type": "ss", "server": server, "port": int(port),
                "cipher": method, "password": password, "ps": urllib.parse.unquote(remarks)
            }

        # --- VMESS 深度优化 ---
        if link.startswith('vmess://'):
            config = json.loads(safe_decode(link[8:].split('#')[0]))
            return {
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port")),
                "uuid": config.get("id"), "aid": int(config.get("aid", 0)),
                "net": config.get("net", "tcp"), "tls": str(config.get("tls")).lower() == "tls",
                "sni": config.get("sni") or config.get("host", ""),
                "path": config.get("path", ""), "ps": config.get("ps", "")
            }
    except: return None

# ==================== 真实运行模拟 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 错误：未找到 nodes.txt")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        unique_links = list(dict.fromkeys([l.strip() for l in f if l.strip()]))

    clash_proxies, rocket_links = [], []
    region_counts = defaultdict(int)

    print(f"🔄 正在处理 {len(unique_links)} 个节点...")

    for link in unique_links:
        p = parse_link(link)
        if not p: continue

        # 模拟地理标注（此处可扩展 IP API）
        tag = "🌍 节点"
        region_counts[tag] += 1
        new_name = f"{tag} {region_counts[tag]:02d} {CHANNEL_MARK}"

        # 1. 构建 Clash 节点 (修复 Screenshot 中的错误)
        if p["type"] == "ss":
            clash_proxies.append({
                "name": new_name, "type": "ss", "server": p["server"], "port": p["port"],
                "cipher": p["cipher"], "password": p["password"], "udp": True
            })
        elif p["type"] == "vmess":
            node = {
                "name": new_name, "type": "vmess", "server": p["server"], "port": p["port"],
                "uuid": p["uuid"], "alterId": p["aid"], "cipher": "auto", "tls": p["tls"],
                "network": p["net"], "skip-cert-verify": True
            }
            if p["net"] == "ws":
                node["ws-opts"] = {"path": p["path"], "headers": {"Host": p["sni"]}}
            clash_proxies.append(node)

        # 2. 构建 iOS 订阅 (URL 编码处理)
        rocket_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}")

    # ==================== 最终写入与校验 ====================
    # 生成规范的 Clash 配置
    clash_final = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [n["name"] for n in clash_proxies], "url": TEST_URL, "interval": 300},
            {"name": "🎯 手动切换", "type": "select", "proxies": ["🚀 自动选择"] + [n["name"] for n in clash_proxies]}
        ],
        "rules": ["MATCH,🚀 自动选择"]
    }

    with open('clash.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(clash_final, f, allow_unicode=True, sort_keys=False)
    
    with open('sub.txt', 'w', encoding='utf-8') as f:
        f.write(base64.b64encode("\n".join(rocket_links).encode()).decode())

    print("✅ 运行日志: 已修复 SS Cipher 逻辑。clash.yaml 与 sub.txt 已生成。")

if __name__ == "__main__":
    main()
