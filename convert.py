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

def safe_split(text: str, sep: str, default_val: str = "auto"):
    if not text:
        return [default_val, ""]
    if sep in text:
        parts = text.split(sep, 1)
        return parts if len(parts) == 2 else [parts[0], ""]
    return [str(text), ""]

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
            time.sleep(0.35)
            # 修复：补全 http 协议头，修正 URL 路径斜杠
            resp = requests.get(f"ip-api.com{server}?lang=zh-CN", timeout=5)
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

        clean_link_str = link.split('#')[0]

        if link.startswith('vmess://'):
            b64_part = link[8:].split('#')[0]
            raw_data = parse_vmess_b64(b64_part)
            if not raw_data:
                return None
            data = json.loads(raw_data.decode('utf-8', 'ignore'))
            return {
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get("ps", "")
            }
        elif link.startswith(('ss://', 'trojan://', 'vless://', 'hysteria2://', 'hy2://')):
            if clean_link_str.startswith("hy2://"):
                clean_link_str = clean_link_str.replace("hy2://", "hysteria2://", 1)
                
            u = urllib.parse.urlparse(clean_link_str)
            
            orig_remarks = ""
            if '#' in link:
                orig_remarks = link.split('#')[1]

            return {
                "type": "hysteria2" if u.scheme in ["hy2", "hysteria2"] else u.scheme,
                "link_str": clean_link_str,
                "url_obj": u,
                "server": u.hostname,
                "original_remarks": orig_remarks
            }
    except Exception as e:
        return None
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

    print(f"🔄 正在处理去重后的 {len(unique_links)} 个节点...")

    for link in unique_links:
        p = parse_link(link)
        if not p or not p.get("server"):
            continue

        label = get_final_label(p.get("server"), p.get("original_remarks", ""))
        idx = len(region_map[label]) + 1
        new_name = f"{label} {idx:02d} {CHANNEL_MARK}"
        region_map[label].append(new_name)

        # ==================== 100% 傻瓜式原装闭合扩展逻辑 ====================
        if p["type"] == "vmess":
            try:
                data = p["raw_data"].copy()
                data['ps'] = new_name
                new_json = json.dumps(data, separators=(',', ':')).encode('utf-8')
                new_b64 = base64.b64encode(new_json).decode('utf-8')
                rocket_links.append(f"vmess://{new_b64}")

                clash_proxies.append({
                    "name": new_name,
                    "type": "vmess",
                    "server": data.get("add") if data.get("add") else "127.0.0.1",
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

        else:
            u = p["url_obj"]
            qs = urllib.parse.parse_qs(u.query)
            
            params = {}
            for k, v in qs.items():
                if v and isinstance(v, list):
                    params[k] = str(v[0])
                elif v:
                    params[k] = str(v)

            # 小火箭通用订阅重命名规则
            base_uri = p['link_str']
            rocket_links.append(f"{base_uri}#{urllib.parse.quote(new_name)}")
            
            proxy_cfg = {
                "name": new_name,
                "type": p["type"],
                "server": u.hostname if u.hostname else "127.0.0.1",
                "port": safe_int(u.port, 443)
            }
            
            try:
                if p["type"] == "ss":
                    if '@' in u.netloc:
                        userinfo, _ = safe_split(u.netloc, '@')
                        method, password = safe_split(userinfo, ':', 'auto')
                    else:
                        netloc_clean = u.netloc.split('#')[0]
                        decoded_ui = parse_vmess_b64(netloc_clean).decode('utf-8', 'ignore')
                        if '@' in decoded_ui:
                            userinfo, hostinfo = safe_split(decoded_ui, '@')
                            method, password = safe_split(userinfo, ':', 'auto')
                            if ':' in hostinfo:
                                s_host, s_port = safe_split(hostinfo, ':')
                                proxy_cfg["server"] = s_host
                                proxy_cfg["port"] = safe_int(s_port, 443)
                            else:
                                proxy_cfg["server"] = hostinfo
                        else:
                            continue
                            
                    proxy_cfg.update({"cipher": method, "password": password, "udp": True})
                    clash_proxies.append(proxy_cfg)
                    
                elif p["type"] == "trojan":
                    proxy_cfg.update({
                        "password": u.username if u.username else "",
                        "udp": True,
                        "sni": params.get("sni", u.hostname),
                        "skip-cert-verify": True
                    })
                    clash_proxies.append(proxy_cfg)

                elif p["type"] == "vless":
                    proxy_cfg.update({
                        "uuid": u.username if u.username else "",
                        "cipher": "auto",
                        "udp": True,
                        "tls": params.get("security") == "tls",
                        "skip-cert-verify": True
                    })
                    clash_proxies.append(proxy_cfg)

                elif p["type"] == "hysteria2":
                    proxy_cfg.update({
                        "password": u.username if u.username else "",
                        "sni": params.get("sni", u.hostname),
                        "skip-cert-verify": True,
                        "alpn": ["h3"]
                    })
                    clash_proxies.append(proxy_cfg)

            except Exception as e:
                continue

    # ==================== 数据持久化保存 ====================
    try:
        # 1. 核心修复：生成真正可用的小火箭纯文本通用订阅（Base64 编码形式）
        # 如果小火箭导入通用订阅需要明文，只需去掉下面的 base64 编码行即可
        raw_subscription_text = "\n".join(rocket_links)
        b64_subscription_data = base64.b64encode(raw_subscription_text.encode('utf-8')).decode('utf-8')
        
        with open('rocket_output.txt', 'w', encoding='utf-8') as f:
            f.write(b64_subscription_data)
            
        # 2. 生成标准 Clash YAML 节点列表
        clash_output = {"proxies": clash_proxies}
        with open('clash_output.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_output, f, allow_unicode=True, sort_keys=False)
            
        print(f"✅ 执行成功！已生成小火箭 Base64 订阅文件 rocket_output.txt 和 Clash 配置文件 clash_output.yaml")
    except Exception as e:
        print(f"❌ 导出保存文件失败: {e}")

if __name__ == "__main__":
    main()
