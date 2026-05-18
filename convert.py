#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

# 自动修复 GitHub Actions 环境隔离导致的 ModuleNotFoundError 错误
try:
    import aiohttp
except ModuleNotFoundError:
    python_path = os.environ.get('pythonLocation')
    if python_path:
        executable = os.path.join(python_path, 'bin', 'python')
        if os.path.exists(executable) and sys.executable != executable:
            os.execv(executable, [executable] + sys.argv)

import asyncio
import base64
import hashlib
import json
import re
import socket
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path

import yaml

CHANNEL_MARK = "@zmxooo"
TEST_URL = "http://www.gstatic.com/generate_204"

CACHE_FILE = "ip_cache.json"
CONFIG_FILE = "config.yaml"
INDEX_FILE = "index.html"
MANIFEST_FILE = "manifest.json"

SEM = asyncio.Semaphore(20)

EMOJI_MAP = {
    "香港": "🇭🇰", "台湾": "🇹🇼", "美国": "🇺🇸", "英国": "🇬🇧", "韩国": "🇰🇷",
    "日本": "🇯🇵", "新加坡": "🇸🇬", "德国": "🇩🇪", "法国": "🇫🇷", "加拿大": "🇨🇦",
    "越南": "🇻🇳", "荷兰": "🇳🇱", "俄罗斯" : "🇷🇺", "俄罗斯联邦": "🇷🇺",
    "马来西亚": "🇲🇾", "泰国": "🇹🇭", "菲律宾": "🇵🇭", "印度": "🇮🇳",
    "印度尼西亚": "🇮🇩", "柬埔寨": "🇰🇭", "澳门": "🇲🇴", "巴基斯坦": "🇵🇰",
    "哈萨克斯坦": "🇰🇿", "土耳其": "🇹🇷", "意大利": "🇮🇹", "西班牙": "🇪🇸",
    "瑞士": "🇨🇭", "瑞典": "🇸🇪", "波兰": "🇵🇱", "乌克兰": "🇺🇦",
    "爱尔兰": "🇮🇪", "奥地利": "🇦🇹", "芬兰": "🇫🇮", "澳大利亚": "🇦🇺",
    "新西兰": "🇳🇿", "巴西": "🇧🇷", "阿根廷": "🇦🇷", "墨西哥": "🇲🇽",
    "智利": "🇨🇱", "阿联酋": "🇦🇪", "沙特阿拉伯": "🇸🇦", "以色列": "🇮🇱",
    "南非": "🇿🇦", "埃及": "🇪🇬"
}

REGION_RULES = [
    ("香港", r"hk|hongkong|香港|🇭🇰"),
    ("台湾", r"tw|taiwan|台湾|臺灣|台湾|中华民国|中華民國|🇹🇼|🇨🇳tw"),
    ("日本", r"jp|japan|日本|东京|東京|大阪|🇯🇵"),
    ("新加坡", r"sg|singapore|新加坡|星加坡|狮城|🇸🇬"),
    ("美国", r"us|unitedstates|美国|美國|美利坚|🇺🇸"),
    ("韩国", r"kr|korea|韩国|韓國|首尔|首爾|🇰🇷"),
    ("英国", r"uk|britain|gb|英国|英國|伦敦|倫敦|🇬🇧"),
    ("德国", r"de|germany|德国|德國|法兰克福|🇩🇪"),
    ("法国", r"fr|france|法国|法國|巴黎|🇫🇷"),
    ("加拿大", r"ca|canada|加拿大|🇨🇦"),
    ("越南", r"vn|vietnam|越南|🇻🇳"),
    ("荷兰", r"nl|netherlands|荷兰|荷蘭|阿姆sterdam|🇳🇱"),
    ("俄罗斯", r"ru|russia|俄罗斯|俄羅斯|莫斯科|俄罗斯联邦|俄羅斯聯邦|🇷🇺"),
    ("澳大利亚", r"au|australia|澳洲|澳大利亚|澳大利亞|悉尼|🇦🇺"),
    ("中国", r"cn|china|中国|中國|内陆|內陸|回国|回國|广东|廣東|🇨🇳")
]

NOISE_WORDS = ["BGP", "IPLC", "IEPL", "VIP", "Premium", "高速", "专线", "节点"]
IP_CACHE = {}
INFO_MARKERS = ["📢", "📡", "🌐"]

def load_cache():
    global IP_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                IP_CACHE = json.load(f)
        except Exception:
            IP_CACHE = {}

def save_cache():
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(IP_CACHE, f, ensure_ascii=False, indent=2)

def atomic_write(path: str, content: str):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)

def safe_b64decode(text: str):
    text = text.strip()
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def is_info_node(name: str):
    return any(x in (name or "") for x in INFO_MARKERS)

def clean_name(name: str):
    text = urllib.parse.unquote(name or "")
    for word in NOISE_WORDS:
        text = text.replace(word, "")
    return re.sub(r"\s+", " ", text).strip() or "未知节点"

async def query_country(session, server):
    if not server:
        return "🌍 其它地区"
        
    # 【修复：无损清洗 IPv6 的中括号，防止 DNS 与 IP 查询崩溃】
    clean_server = server.strip("[]")
    
    if clean_server in IP_CACHE:
        return IP_CACHE[clean_server]

    try:
        # 【修复：将同步阻塞的 socket 转换为异步线程池执行，解放事件循环】
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, socket.gethostbyname, clean_server)
    except Exception:
        return "🌍 其它地区"

    async with SEM:
        try:
            url = f"http://ip-api.com/json/{clean_server}?lang=zh-CN"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                data = await resp.json()
                if data.get("status") == "success":
                    country = data.get("country", "其它地区")
                    emoji = EMOJI_MAP.get(country, "🌍")
                    result = f"{emoji} {country}"
                    IP_CACHE[clean_server] = result
                    return result
        except Exception:
            pass
    return "🌍 其它地区"

async def get_final_label(session, server, remarks):
    if is_info_node(remarks):
        return remarks.strip()
    text = clean_name(remarks).lower()
    for region, pattern in REGION_RULES:
        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(region, '🌍')} {region}"
    return await query_country(session, server)

def validate(proxy):
    if not isinstance(proxy, dict):
        return False
    
    # 基础必填项校验
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    # 补充端口合法性校验：避免非数字/无效端口
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return False
    except (ValueError, TypeError):
        return False
    
    ptype = proxy.get("type")
    
    # VMess协议：补充关键参数校验
    if ptype == "vmess":
        if not proxy.get("uuid"):
            return False
        # 网络类型为ws/grpc时，补充对应必填项
        network = proxy.get("network", "tcp").lower()
        if network == "ws" and not proxy.get("ws-opts", {}).get("path"):
            return False
        if network == "grpc" and not proxy.get("grpc-opts", {}).get("grpc-service-name"):
            return False
        return True
    
    # VLESS协议：Reality模式补充公钥校验
    elif ptype == "vless":
        if not proxy.get("uuid"):
            return False
        if proxy.get("security") == "reality" and not proxy.get("reality-opts", {}).get("public-key"):
            return False
        return True
    
    # TUIC协议：补充必填参数
    elif ptype == "tuic":
        return bool(proxy.get("uuid") and proxy.get("password"))
    
    # Trojan/Hysteria2协议：基础校验
    elif ptype in ["trojan", "hysteria2"]:
        return bool(proxy.get("password"))
    
    # SS协议：加密方式白名单+参数完整性
    elif ptype == "ss":
        cipher = proxy.get("cipher")
        password = proxy.get("password")
        if not (cipher and password):
            return False
        # 拦截明显无效的加密方式，避免配置后连不上
        SUPPORTED_SS_CIPHERS = {
            "auto", "aes-128-gcm", "aes-256-gcm",
            "chacha20-poly1305", "chacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"
        }
        if cipher.lower() not in SUPPORTED_SS_CIPHERS:
            print(f"[校验不通过] SS加密方式不支持：{cipher}")
            return False
        return True
    
    # 未知协议直接不通过
    return False


class Parser:
    @staticmethod
    async def parse(session, link):
        """核心分发器：【已全面打通，支持全协议分发路由】"""
        try:
            link = link.strip()
            if link.startswith("ss://"):
                return await Parser.parse_ss(session, link)
            elif link.startswith("vmess://"):
                return await Parser.parse_vmess(session, link)
            elif link.startswith("vless://"):
                return await Parser.parse_vless(session, link)
            elif link.startswith("trojan://"):
                return await Parser.parse_trojan(session, link)
            elif link.startswith("hy2://") or link.startswith("hysteria2://"):
                return await Parser.parse_hy2(session, link)
            elif link.startswith("tuic://"):
                return await Parser.parse_tuic(session, link)
        except Exception:
            return None
        return None

    @staticmethod
    async def parse_ss(session, link):
        """
        Shadowsocks (SS) 节点核心解析函数【已统一整合精简，完美支持 SIP002、复杂密码与插件】
        """
        try:
            remarks = "SS节点"
            if "#" in link:
                link, rem = link.split("#", 1)
                remarks = urllib.parse.unquote(rem.strip())

            raw = link[5:].strip()
            if not raw:
                return None

            # 兼容处理 Legacy 全加密旧格式
            if "@" not in raw:
                try:
                    raw = safe_b64decode(raw)
                except Exception:
                    return None

            if not raw or "@" not in raw:
                return None

            # 从右往左切分 @ 字符，隔离防止用户密码中包含 @
            auth, endpoint = raw.rsplit("@", 1)

            # 解析 SIP002 独立加密的 Userinfo
            if ":" not in auth:
                try:
                    auth = safe_b64decode(auth)
                except Exception:
                    return None

            if not auth or ":" not in auth:
                return None

            # 分离加密方法与密码，支持密码中含有冒号
            auth_parts = auth.split(":", 1)
            if len(auth_parts) != 2:
                return None
            cipher, password = auth_parts[0].strip().lower().replace("_", "-"), auth_parts[1]

            if not cipher or not password:
                return None

            # 加密算法白名单安全清洗
            if cipher not in {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "none", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}:
                cipher = "aes-256-gcm"

            # 剥离 Query 与 Path 参数并安全提取 plugin
            plugin = None
            if "?" in endpoint:
                endpoint, query = endpoint.split("?", 1)
                params = urllib.parse.parse_qs(query)
                if "plugin" in params:
                    plugin = params["plugin"][0]
            if "/" in endpoint:
                endpoint = endpoint.split("/", 1)[0]

            endpoint = endpoint.strip().rstrip("/")

import urllib.parse
import re

@staticmethod
async def parse_ss(session, link: str):
    """
    极简高性能 Shadowsocks 解析器
    支持全格式、全场景，确保显示且有网络
    """
    try:
        if not link:
            return None
            
        link = link.strip()
        
        # 1. 提取备注
        remarks = "SS节点"
        if "#" in link:
            link, rem = link.split("#", 1)
            remarks = urllib.parse.unquote(rem.strip()) or remarks

        # 2. 剥离协议头 (严格限制 ss://)
        if link.lower().startswith("ss://"):
            raw = link[5:]
        else:
            return None

        # 3. 处理整段Base64编码
        if "@" not in raw:
            try:
                raw = safe_b64decode(raw)
            except Exception:
                return None

        if "@" not in raw:
            return None

        # 4. 彻底剥离 URL 参数 (如 ?plugin=xxx), 确保 endpoint 纯净
        # 这一步是确保非 8388 端口及 IPv6 节点能百分百连通的关键
        if "?" in raw:
            raw, _ = raw.split("?", 1)

        # 5. 切分认证与地址
        auth, endpoint = raw.rsplit("@", 1)

        # 6. 处理认证信息 (兼容未 Base64 的原始明文和加密明文)
        if ":" not in auth:
            try:
                auth = safe_b64decode(auth)
            except Exception:
                return None

        if ":" not in auth:
            return None

        # URL 解码认证信息，防止密码中的特殊字符（如 +, /, =）变形
        auth = urllib.parse.unquote(auth)
        
        cipher_raw, _, password = auth.partition(":")
        cipher_raw = cipher_raw.strip().lower()

        # 7. 加密方式精准映射
        CIPHER_ALIASES = {
            "chacha20-poly1305": "chacha20-ietf-poly1305",
            "none": "none"  # 除非明确兼容特定内核，否则保持 none 比 auto 更不容易在核心里报错
        }
        cipher = CIPHER_ALIASES.get(cipher_raw, cipher_raw)

        # 8. 解析地址与端口 (此时 endpoint 绝不含 ?)
        if endpoint.startswith("["):
            match = re.match(r"\[(.+)\]:(\d+)", endpoint)
            if not match:
                return None
            server = match.group(1)
            port = int(match.group(2))
        else:
            endpoint_parts = endpoint.rsplit(":", 1)
            if len(endpoint_parts) < 2:
                return None
            server, port_str = endpoint_parts
            try:
                port = int(port_str)
            except Exception:
                port = 8388

        if not server:
            return None

        # 9. 最终标签
        label = await get_final_label(session, server, remarks)

        return {
            "name": label,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": cipher,
            "password": password,
            "udp": True
        }
    except Exception:
        return None

    @staticmethod
    async def parse_vmess(session, link):
        _orig_link = str(link)
        try:
            link = str(link).strip().replace("vmess://vmess://", "vmess://")
            if not link.startswith("vmess://"):
                return None

            link_main_part = link[8:]
            url_part, _, fragment_part = link_main_part.partition("#")
            raw_part = url_part.strip()
            if not raw_part:
                return None

            decoded = ""
            is_json_vmess = False
            data = {}

            try:
                decoded = safe_b64decode(raw_part).strip()
                if decoded.startswith("{") and decoded.endswith("}"):
                    is_json_vmess = True
                    data = json.loads(decoded)
            except Exception:
                pass

            if is_json_vmess and data:
                server = str(data.get("add") or data.get("server") or "").strip()
                if not server: return None
                uuid = str(data.get("id") or data.get("uuid") or "").strip()
                if not uuid: return None

                network = str(data.get("net") or data.get("type") or "tcp").lower().strip()
                if network not in {"tcp", "ws", "grpc", "http", "h2"}:
                    network = "tcp"

                try:
                    port = int(data.get("port") or 443)
                except Exception:
                    port = 443

                try:
                    aid = int(data.get("aid") or 0)
                except Exception:
                    aid = 0

                tls_raw = data.get("security") or data.get("tls") or ""
                tls = str(tls_raw).lower() in ("1", "true", "tls", "on", "reality")

                sni = str(data.get("sni") or data.get("host") or "").strip()
                host = str(data.get("host") or data.get("sni") or server).strip()
                path = urllib.parse.unquote(str(data.get("path") or "/"))
                remarks = str(data.get("ps") or "VMess节点").strip()

                label = await get_final_label(session, server, remarks)

                raw_cipher = str(data.get("scy") or data.get("cipher") or "auto").strip().lower()
                final_cipher = raw_cipher if raw_cipher in {"auto", "aes-128-gcm", "chacha20-poly1305", "none"} else "auto"

                proxy = {
                    "name": label, "type": "vmess", "server": server, "port": port,
                    "uuid": uuid, "alterId": aid, "cipher": final_cipher, "network": network,
                    "tls": tls, "skip-cert-verify": True
                }

                if sni: proxy["sni"] = sni
                if network == "ws":
                    if not path.startswith("/"): path = "/" + path
                    headers = {"Host": host} if host and host.lower() != server.lower() else {}
                    proxy["ws-opts"] = {"path": path}
                    if headers: proxy["ws-opts"]["headers"] = headers
                elif network == "grpc":
                    service_name = (data.get("serviceName") or data.get("servicename") or data.get("service-name") or data.get("ns") or "").strip()
                    if not service_name:
                        path_value = str(data.get("path") or "").strip()
                        if path_value and not path_value.startswith("/"):
                            service_name = path_value
                    if service_name:
                        proxy["grpc-opts"] = {"grpc-service-name": service_name}

                if data.get("flow"): proxy["flow"] = data["flow"]
                return proxy

            else:
                u = urllib.parse.urlparse(f"vmess://{raw_part}")
                if not u.hostname:
                    try:
                        retry_decode = safe_b64decode(raw_part).strip()
                        if retry_decode and not (retry_decode.startswith("{") and retry_decode.endswith("}")):
                            u = urllib.parse.urlparse(f"vmess://{retry_decode}")
                    except Exception:
                        pass

                hostname = str(u.hostname or "").strip()
                if not hostname: return None
                uuid = str(u.username or "").strip()
                if not uuid: return None

                remarks = urllib.parse.unquote(fragment_part or "VMess节点").strip()
                q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}

                try:
                    port = u.port
                except ValueError:
                    port = None
                if port is None:
                    try:
                        port = int(u.netloc.rsplit(":", 1)[-1].split("/")[0])
                    except Exception:
                        port = 443

                network = str(q.get("type") or q.get("net") or "tcp").lower().strip()
                tls_raw = q.get("security") or q.get("tls") or ""
                tls = str(tls_raw).lower() in ("1", "true", "tls", "on", "reality")

                sni = str(q.get("sni") or q.get("host") or "").strip()
                host = str(q.get("host") or q.get("sni") or hostname).strip()
                path = urllib.parse.unquote(str(q.get("path") or "/"))

                label = await get_final_label(session, hostname, remarks)
                raw_cipher = str(q.get("scy") or q.get("cipher") or "auto").strip().lower()
                final_cipher = raw_cipher if raw_cipher in {"auto", "aes-128-gcm", "chacha20-poly1305", "none"} else "auto"

                proxy = {
                    "name": label, "type": "vmess", "server": hostname, "port": port,
                    "uuid": uuid, "alterId": 0, "cipher": final_cipher, "network": network,
                    "tls": tls, "skip-cert-verify": True
                }

                if sni: proxy["sni"] = sni
                if network == "ws":
                    if not path.startswith("/"): path = "/" + path
                    headers = {"Host": host} if host and host.lower() != hostname.lower() else {}
                    proxy["ws-opts"] = {"path": path}
                    if headers: proxy["ws-opts"]["headers"] = headers
                elif network == "grpc":
                    service_name = (q.get("servicename") or q.get("service_name") or q.get("service-name") or q.get("ns") or "").strip()
                    if not service_name:
                        path_value = str(q.get("path") or "").strip()
                        if path_value and not path_value.startswith("/"):
                            service_name = path_value
                    if service_name:
                        proxy["grpc-opts"] = {"grpc-service-name": service_name}

                if q.get("flow"): proxy["flow"] = q["flow"]
                return proxy
        except Exception as e:
            print(f"[VMESS PARSE ERROR] {e} -> {_orig_link}")
            return None

    @staticmethod
    async def parse_vless(session, link):
        try:
            u = urllib.parse.urlparse(link)
            q = dict(urllib.parse.parse_qsl(u.query))
            label = await get_final_label(session, u.hostname, u.fragment)
            proxy = {
                "name": label, "type": "vless", "server": u.hostname, "port": int(u.port or 443),
                "uuid": u.username, "network": q.get("type", "tcp"),
                "tls": q.get("security") in ["tls", "reality"],
                "servername": q.get("sni") or u.hostname, "client-fingerprint": q.get("fp", "chrome"),
                "skip-cert-verify": True
            }
            if q.get("security") == "reality":
                proxy["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", u.hostname)}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
            return proxy
        except Exception:
            return None

    @staticmethod
    async def parse_trojan(session, link):
        try:
            u = urllib.parse.urlparse(link)
            label = await get_final_label(session, u.hostname, u.fragment)
            return {
                "name": label, "type": "trojan", "server": u.hostname, "port": int(u.port or 443),
                "password": u.username, "sni": u.hostname, "skip-cert-verify": True
            }
        except Exception:
            return None

    @staticmethod
    async def parse_hy2(session, link):
        try:
            if link.startswith("hy2://"):
                link = link.replace("hy2://", "hysteria2://", 1)
            u = urllib.parse.urlparse(link)
            q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query)}
            remarks = urllib.parse.unquote(u.fragment or "Hysteria2节点")
            
            hostname = u.hostname
            if not hostname: return None
            if hostname.startswith("[") and hostname.endswith("]"):
                hostname = hostname[1:-1]

            label = await get_final_label(session, hostname, remarks)
            try:
                port = u.port
            except ValueError:
                port = None
            if not port:
                netloc_parts = u.netloc.rsplit(":", 1)
                if len(netloc_parts) == 2 and netloc_parts[1].split("/")[0].isdigit():
                    port = int(netloc_parts[1].split("/")[0])
                else:
                    port = 443

            proxy = {
                "name": label, "type": "hysteria2", "server": hostname, "port": port,
                "password": u.username or "", "sni": q.get("sni") or hostname, "skip-cert-verify": True
            }
            if q.get("obfs"):
                proxy["obfs"] = q.get("obfs")
                if q.get("obfs-password"): proxy["obfs-password"] = q.get("obfs-password")
            return proxy
        except Exception:
            return None

    @staticmethod
    async def parse_tuic(session, link):
        try:
            u = urllib.parse.urlparse(link)
            q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query)}
            remarks = urllib.parse.unquote(u.fragment or "TUIC节点")
            
            hostname = u.hostname
            if not hostname: return None
            if hostname.startswith("[") and hostname.endswith("]"):
                hostname = hostname[1:-1]

            label = await get_final_label(session, hostname, remarks)
            try:
                port = u.port
            except ValueError:
                port = None
            if not port:
                netloc_parts = u.netloc.rsplit(":", 1)
                if len(netloc_parts) == 2 and netloc_parts[1].split("/")[0].isdigit():
                    port = int(netloc_parts[1].split("/")[0])
                else:
                    port = 443

            uuid_str = u.username or ""
            password_str = u.password or q.get("pass") or ""

            if not uuid_str and u.netloc and "@" in u.netloc:
                user_info = u.netloc.rsplit("@", 1)[0]
                if ":" in user_info:
                    uuid_str, password_str = user_info.split(":", 1)
                else:
                    uuid_str = user_info

            if not uuid_str: return None
            return {
                "name": label, "type": "tuic", "server": hostname, "port": port,
                "uuid": str(uuid_str).strip(), "password": str(password_str).strip(),
                "alpn": [q.get("alpn", "h3")], "congestion-controller": q.get("congestion_control", "bbr"),
                "sni": q.get("sni") or hostname, "skip-cert-verify": True
            }
        except Exception:
            return None


async def build():
    load_cache()
    path = Path("nodes.txt")
    if not path.exists():
        print("nodes.txt not found")
        return

    links = [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]

    region_map = defaultdict(list)
    clash_proxies = []
    rocket_links = []
    seen = set()
    used_names = set()

    connector = aiohttp.TCPConnector(ssl=False, limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        for link in links:
            proxy = await Parser.parse(session, link)
            if not proxy:
                continue

            fp = (proxy.get("server"), proxy.get("port"), proxy.get("type"), proxy.get("uuid"), proxy.get("password"))
            if fp in seen:
                continue
            seen.add(fp)

            label = proxy["name"]
            if is_info_node(proxy["name"]):
                clash_proxies.append(proxy)
                rocket_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(proxy['name'])}")
                continue

            idx = len(region_map[label]) + 1
            proxy["name"] = f"{label} {idx:02d}"

            if validate(proxy):
                base_name = proxy["name"]
                port_val = proxy.get("port", 443)
                if proxy["name"] in used_names:
                    proxy["name"] = f"{base_name.strip()}-{port_val}"
                
                loop_idx = 1
                while proxy["name"] in used_names:
                    proxy["name"] = f"{base_name.strip()}-{port_val}-{loop_idx}"
                    loop_idx += 1
                
                used_names.add(proxy["name"])
                clash_proxies.append(proxy)
                region_map[label].append(proxy["name"])

            rocket_links.append(f"{link.split('#')[0]}#{urllib.parse.quote(proxy['name'])}")

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["🎬 自动选择", "🎯 手动选择"] + list(region_map.keys()) + ["DIRECT"]
            },
            {
                "name": "🎬 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "proxies": [x["name"] for x in clash_proxies if not is_info_node(x["name"])]
            },
            {
                "name": "🎯 手动选择",
                "type": "select",
                "proxies": [x["name"] for x in clash_proxies]
            }
        ],
        "rules": ["MATCH,🚀 节点选择"]
    }
    info_names = [x["name"] for x in clash_proxies if is_info_node(x["name"])]

    for region, proxies in region_map.items():
        if proxies:
            config["proxy-groups"].append({
                "name": region,
                "type": "select",
                "proxies": info_names + proxies
            })

    yaml_text = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    atomic_write(CONFIG_FILE, yaml_text)

    sub = base64.b64encode("\n".join(rocket_links).encode()).decode()
    atomic_write(INDEX_FILE, sub)

    atomic_write(MANIFEST_FILE, json.dumps({
        "generated_at": int(time.time()),
        "node_count": len(clash_proxies),
        "hash": hashlib.sha256(yaml_text.encode()).hexdigest()
    }, indent=2))

    save_cache()
    print(f"Generated {len(clash_proxies)} nodes")

if __name__ == "__main__":
    asyncio.run(build())
