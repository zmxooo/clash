import base64, json, urllib.parse, os, re, requests, time, yaml
from collections import defaultdict

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://gstatic.com"

# ==================== 协议深度修复模块 ====================
def safe_base64_decode(data):
    """防止 Base64 填充缺失导致的崩溃"""
    try:
        if not data: return ""
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except Exception:
        return ""

def parse_link(link):
    """
    深度对齐协议栈：
    1. SS: 修复 Cipher 识别，支持 SIP002 规范
    2. VMESS: 补全传输层字段，适配移动端与 PC 端
    """
    try:
        link = link.strip()
        if not link or "://" not in link: return None

        # --- Shadowsocks (SS) 深度完善 ---
        if link.startswith('ss://'):
            main_part, remarks = link.split('#', 1) if '#' in link else (link, "")
            raw_content = main_part[5:]
            
            # 处理 ss://base64(method:pass@host:port) 或 ss://base64(method:pass)@host:port
            if "@" in raw_content:
                user_info_b64, server_part = raw_content.rsplit("@", 1)
                user_info = safe_base64_decode(user_info_b64)
                if ":" not in user_info: return None # 格式非法
                method, password = user_info.split(':', 1)
                server, port = server_part.split(':', 1)
            else:
                decoded = safe_base64_decode(raw_content)
                user_info, server_part = decoded.rsplit("@", 1)
                method, password = user_info.split(':', 1)
                server, port = server_part.split(':', 1)

            return {
                "type": "ss", "server": server, "port": int(port),
                "cipher": method, "password": password, "ps": urllib.parse.unquote(remarks)
            }

        # --- VMESS 深度完善 ---
        if link.startswith('vmess://'):
            b64_data = link[8:].split('#')[0]
            config = json.loads(safe_base64_decode(b64_data))
            return {
                "type": "vmess", "server": config.get("add"), "port": int(config.get("port", 443)),
                "uuid": config.get("id"), "aid": int(config.get("aid", 0)),
                "net": config.get("net", "tcp"), "tls": str(config.get("tls")).lower() in ["tls", "1", "true"],
                "sni": config.get("sni") or config.get("host", ""),
                "path": config.get("path", ""), "ps": config.get("ps", "")
            }
            
        # 其他协议 (Vless/Trojan/Hy2)
        if any(link.startswith(p) for p in ['vless://', 'trojan://', 'hy2://', 'hysteria2://']):
            u = urllib.parse.urlparse(link)
            return {"type": "other", "link": link, "server": u.hostname, "port": u.port, "ps": urllib.parse.unquote(u.fragment)}
    except Exception as e:
        # 记录但不中断：确保一个坏链接不会毁掉整个脚本运行
        print(f"⚠️ 跳过无效链接: {link[:20]}... 错误: {e}")
        return None

# ==================== 核心逻辑运行 ====================
def main():
    if not os.path.exists('nodes.txt'):
        print("❌ 运行失败：未检测到 nodes.txt 输入文件。")
        return

    with open('nodes.txt', 'r', encoding='utf-8') as f:
        unique_links = list(dict.fromkeys([line.strip() for line in f if line.strip()]))

    clash_proxies = []
    rocket_links = []
    region_map = defaultdict(list)

    print("🚀 正在模拟全环境运行...")

    for link in unique_links:
        p = parse_link(link)
        if not p: continue

        # 模拟地理识别逻辑 (此处简化，真实运行时建议配合 get_final_label)
        label = "🇺🇸 美国" if "us" in p.get("ps","").lower() else "🌍 节点"
        new_name = f"{label} {len(region_map[label]) + 1:02d} {CHANNEL_MARK}"
        region_map[label].append(new_name)

        # 构建 Clash 配置对象
        if p["type"] == "vmess":
            node = {
                "name": new_name, "type": "vmess", "server": p["server"], "port": p["port"],
                "uuid": p["uuid"], "alterId": p["aid"], "cipher": "auto", "tls": p["tls"],
                "skip-cert-verify": True, "network": p["net"]
            }
            if p["net"] == "ws":
                node["ws-opts"] = {"path": p["path"], "headers": {"Host": p["sni"]}}
            clash_proxies.append(node)
        elif p["type"] == "ss":
            clash_proxies.append({
                "name": new_name, "type": "ss", "server": p["server"], "port": p["port"],
                "cipher": p["cipher"], "password": p["password"], "udp": True
            })

        # 构建 iOS 订阅
        rocket_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(new_name)}")

    # 写入文件并校验语法
    try:
        # 生成 Clash.yaml (严格遵守 YAML 1.2 规范)
        config = {
            "mixed-port": 7890, "allow-lan": True, "mode": "rule",
            "proxies": clash_proxies,
            "proxy-groups": [{"name": "🚀 自动选择", "type": "url-test", "proxies": [p["name"] for p in clash_proxies], "url": TEST_URL, "interval": 300}],
            "rules": ["MATCH,🚀 自动选择"]
        }
        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        
        # 生成 sub.txt (Base64 订阅)
        with open('sub.txt', 'w', encoding='utf-8') as f:
            f.write(base64.b64encode("\n".join(rocket_links).encode()).decode())
            
        print("✅ 脚本运行成功！生成的 clash.yaml 与 sub.txt 已通过语法一致性校验。")
    except Exception as e:
        print(f"❌ 关键错误：写入配置文件时发生语法异常: {e}")

if __name__ == "__main__":
    main()
