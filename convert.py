import base64
import json
import urllib.parse
import re

# ==================== 核心加固引擎 ====================

def universal_decode(data: str) -> str:
    """
    【加固 1：万能解码】
    解决填充缺失、URL 安全字符、以及由于粘贴导致的非法换行/空格。
    """
    if not data: return ""
    # 彻底清理：只保留 Base64 允许的字符
    data = re.sub(r'[^a-zA-Z0-9+/=_-]', '', data)
    # 转换 URL 安全格式
    data = data.replace('-', '+').replace('_', '/')
    # 自动补全 Padding (Base64 长度必须是 4 的倍数)
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except Exception:
        return ""

def sanitize_host(value: str) -> str:
    """
    【加固 2：深度清洗】
    从 "https://google.com:443/path" 这种脏数据中提取纯净的域名或 IP。
    这是防止客户端（如 Clash/小火箭）解析失败的关键。
    """
    if not value: return ""
    decoded = urllib.parse.unquote(value).strip()
    # 移除协议头
    if "://" in decoded:
        decoded = decoded.split("://")[-1]
    # 移除路径、端口和多余空格
    return decoded.split('/')[0].split(':')[0].split('?')[0].strip()

# ==================== 分协议强化工厂 ====================

def parse_proxy_link(link: str):
    link = link.strip()
    if not link or "://" not in link:
        return None

    # 【加固 3：预处理】先剥离备注，防止备注里的 # ? @ 符号干扰主 URL 解析
    parts = link.split('#', 1)
    main_url = parts[0]
    remarks = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

    try:
        # --- VMESS: 解决 JSON 字段不全和 Base64 截断 ---
        if main_url.startswith('vmess://'):
            config_json = universal_decode(main_url[8:])
            if not config_json: return None
            data = json.loads(config_json)
            server = data.get("add", "")
            # 备注优先级：URL 外部 > JSON 内部
            final_remarks = remarks if remarks else data.get("ps", "")
            return {
                "type": "vmess",
                "server": server,
                "port": int(data.get("port", 443)),
                "uuid": data.get("id"),
                "net": data.get("net", "tcp"),
                "path": data.get("path", ""),
                "tls": "tls" if str(data.get("tls")).lower() in ["tls", "1", "true"] else "",
                "sni": sanitize_host(data.get("sni", server)),
                "remarks": final_remarks
            }

        # --- VLESS/TROJAN: 解决 Reality 关键参数丢失 ---
        elif main_url.startswith(('vless://', 'trojan://')):
            u = urllib.parse.urlparse(main_url)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            return {
                "type": u.scheme,
                "server": u.hostname,
                "port": u.port or 443,
                "uuid": u.username,      # vless
                "password": u.username,  # trojan
                "security": q.get("security", ""),
                "sni": sanitize_host(q.get("sni", u.hostname)),
                "pbk": q.get("pbk", ""), # Reality 必备
                "sid": q.get("sid", ""), # Reality 必备
                "fp": q.get("fp", ""),   # 指纹
                "net": q.get("type", "tcp"),
                "path": q.get("path", ""),
                "serviceName": q.get("serviceName", ""), # gRPC
                "remarks": remarks
            }

        # --- HYSTERIA 2: 兼容 hy2 协议名与 auth 提取 ---
        elif main_url.startswith(('hysteria2://', 'hy2://')):
            u = urllib.parse.urlparse(main_url)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            auth = u.username if u.username else q.get("auth", "")
            return {
                "type": "hysteria2",
                "server": u.hostname,
                "port": u.port or 443,
                "auth": auth,
                "sni": sanitize_host(q.get("sni", u.hostname)),
                "remarks": remarks
            }

        # --- SHADOWSOCKS: 彻底修复 SIP002 格式与插件丢失 ---
        elif main_url.startswith('ss://'):
            content = main_url[5:]
            # SIP002: ss://base64(method:pass)@host:port
            if '@' in content:
                user_part, addr_part = content.split('@', 1)
                user_info = universal_decode(user_part)
                if ':' not in user_info: return None
                method, password = user_info.split(':', 1)
                
                # 提取地址、端口及插件参数
                addr_split = addr_part.split('/?', 1)
                hp = addr_split[0].split(':')
                server = hp[0]
                port = int(hp[1]) if len(hp) > 1 else 8388
                
                plugin = ""
                if len(addr_split) > 1:
                    plugin = urllib.parse.unquote(urllib.parse.parse_qs(addr_split[1]).get("plugin", [""])[0])
            else:
                # Legacy: ss://base64(method:pass@host:port)
                decoded = universal_decode(content)
                if '@' in decoded:
                    user_info, addr_info = decoded.rsplit('@', 1) # 从右切，防止密码里有 @
                    if ':' not in user_info: return None
                    method, password = user_info.split(':', 1)
                    hp = addr_info.split(':')
                    server, port = hp[0], int(hp[1])
                    plugin = ""
                else: return None

            return {
                "type": "ss",
                "server": server,
                "port": port,
                "method": method,
                "password": password,
                "plugin": plugin,
                "remarks": remarks
            }

    except Exception as e:
        # 记录异常但保持运行
        print(f"解析失败: {link[:30]}... 错误: {e}")
        return None
