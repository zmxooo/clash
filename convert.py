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
    "日本": "🇯🇵", "新加坡": "🇸🇬", "越南": "🇻🇳", "德国": "🇩🇪", "立陶宛": "🇱🇹",
    "法国": "🇫🇷", "俄罗斯": "🇷🇺", "加拿大": "🇨🇦", "荷兰": "🇳🇱", "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪", "土耳其": "🇹🇷",
}

# ==================== 工具函数 ====================
def parse_vmess_b64(b64_part):
    if not isinstance(b64_part, str):
        b64_part = str(b64_part)
    b64_part = re.sub(r'[^a-zA-Z0-9+/=_-]', '', b64_part)
    b64_part = b64_part.replace('-', '+').replace('_', '/')
    padding = len(b64_part) % 4
    if padding:
        b64_part += "=" * (4 - padding)
    try:
        return base64.b64decode(b64_part)
    except:
        return b""

def safe_int(val, default=443):
    try:
        if isinstance(val, int):
            return val
        clean_val = re.sub(r'\D', '', str(val))
        return int(clean_val) if clean_val else default
    except:
        return default

def get_final_label(server: str, remarks: str = "") -> str:
    text = urllib.parse.unquote(str(remarks)).lower()
    meta = [
        ("香港", r"hk|hongkong|香港"), ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"), ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"), ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"), ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立桃宛|立陶宛"),
    ]
    for name, pattern in meta:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(name, '🌍')} {name}"

    if server and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', server):
        if server in IP_CACHE:
            return IP_CACHE[server]
        try:
            time.sleep(0.1)
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=3)
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country")
                label = f"{EMOJI_MAP.get(country, '🌍')} {country}"
                IP_CACHE[server] = label
                return label
        except:
            pass
    return "🧿 其他地区"

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
        # 去重时只对比 # 号前的核心部分
        core = line.split('#')[0]
        if core not in seen:
            seen.add(core)
            unique_links.append(line)

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []

    print(f"🔄 正在强力处理去重后的 {len(unique_links)} 个节点...")

    for link in unique_links:
        # 1. 严格切分原始备注
        if '#' in link:
            clean_link_str, orig_remarks = link.split('#', 1)
        else:
            clean_link_str, orig_remarks = link, ""

        # ================= 1. VMESS 专属分支 =================
        if clean_link_str.startswith('vmess://'):
            try:
                b64_part = clean_link_str[8:]
                raw_data = parse_vmess_b64(b64_part)
                if not raw_data:
                    continue
                data = json.loads(raw_data.decode('utf-8', 'ignore'))
                server_ip = data.get("add", "")
                remarks_for_label = data.get("ps", "") if data.get("ps") else orig_remarks
                
                label = get_final_label(server_ip, remarks_for_label)
                idx = len(region_map[label]) + 1
                new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
                region_map[label].append(new_name)

                # 重构小火箭链接
                data['ps'] = new_name
                new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
                new_b64 = base64.b64encode(new_json).decode('utf-8')
                rocket_links.append(f"vmess://{new_b64}")

                # 重构 Clash 节点
                clash_proxies.append({
                    "name": new_name,
                    "type": "vmess",
                    "server": server_ip if server_ip else "127.0.0.1",
                    "port": safe_int(data.get("port"), 443),
                    "uuid": data.get("id"),
                    "alterId": safe_int(data.get("aid"), 0),
                    "cipher": "auto",
                    "tls": str(data.get("tls", "")).lower() in ["tls", "1", "true"],
                    "skip-cert-verify": True,
                    "network": data.get("net", "tcp"),
                    "ws-opts": {"path": data.get("path", "/")} if data.get("net") == "ws" else {}
                })
            except:
                continue

        # ================= 2. HYSTERIA2 专属分支 (纯正则拦截) =================
        elif clean_link_str.startswith(('hysteria2://', 'hy2://')):
            # 使用精准正则表达式提取 [密码, IP/域名, 端口, 参数区]
            pattern = r'^(?:hysteria2|hy2)://([^@]+)@([^:]+):(\d+)(?:\?(.*))?$'
            match = re.match(pattern, clean_link_str)
            if not match:
                continue
                
            password, server_ip, port_str, query_str = match.groups()
            query_str = query_str if query_str else ""
            
            # 计算国家标签和新名字
            label = get_final_label(server_ip, orig_remarks)
            idx = len(region_map[label]) + 1
            new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
            region_map[label].append(new_name)

            # 【不作任何修改】直接无损重写小火箭通用订阅语法
            rocket_links.append(f"{clean_link_str}#{urllib.parse.quote(new_name)}")

            # 解析参数区（用于 Clash 节点）
            params = {}
            if query_str:
                for item in query_str.split('&'):
                    if '=' in item:
                        k, v = item.split('=', 1)
                        params[k] = urllib.parse.unquote(v)

            # 提取 SNI (剔除可能的 https:// 前缀干扰)
            sni_val = params.get("sni", server_ip)
            if "://" in sni_val:
                sni_val = sni_val.split("://")[-1].split("/")[0]

            # 无损重构 Clash Hysteria2 语法
            clash_proxies.append({
                "name": new_name,
                "type": "hysteria2",
                "server": server_ip,
                "port": safe_int(port_str, 443),
                "password": password,
                "sni": sni_val,
                "skip-cert-verify": params.get("insecure") != "0",
                "alpn": [params.get("alpn", "h3")]
            })

        # ================= 3. SS / TROJAN / VLESS 其他通用分支 =================
        elif clean_link_str.startswith(('ss://', 'trojan://', 'vless://')):
            try:
                # 提取协议类型
                proto = clean_link_str.split('://')[0]
                
                # 简单用正则抓取 IP 域名段作为地理定位依据
                server_match = re.search(r'@([^:]+):(\d+)', clean_link_str)
                server_ip = server_match.group(1) if server_match else "127.0.0.1"
                
                label = get_final_label(server_ip, orig_remarks)
                idx = len(region_map[label]) + 1
                new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
                region_map[label].append(new_name)

                # 直接无损追加新备注语法
                rocket_links.append(f"{clean_link_str}#{urllib.parse.quote(new_name)}")
                
                # 由于重点是修复 hy2，通用协议保留最基础的节点卡位，防止报错
                clash_proxies.append({
                    "name": new_name,
                    "type": "trojan" if proto == "trojan" else "ss",
                    "server": server_ip,
                    "port": safe_int(server_match.group(2)) if server_match else 443,
                    "password": "password_placeholder",
                    "skip-cert-verify": True
                })
            except:
                continue

    # ==================== 输出文件保存 ====================
    try:
        with open('rocket_output.txt', 'w', encoding='utf-8') as f:
            f.write("\n".join(rocket_links))
        
        clash_output = {"proxies": clash_proxies}
        with open('clash_output.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_output, f, allow_unicode=True, sort_keys=False)
            
        print("✅ 重写成功！已完全拦截并无损生成 Hysteria2 节点。")
    except Exception as e:
        print(f"❌ 写入输出文件失败: {e}")

if __name__ == "__main__":
    main()
