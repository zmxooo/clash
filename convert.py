import sys
import os

# 自动修复 GitHub Actions 环境隔离导致的 ModuleNotFoundError 错误
try:
    import aiohttp
except ModuleNotFoundError:
    # 检查是否在 GitHub Actions 虚拟环境中
    python_path = os.environ.get('pythonLocation')
    if python_path:
        executable = os.path.join(python_path, 'bin', 'python')
        if os.path.exists(executable) and sys.executable != executable:
            os.execv(executable, [executable] + sys.argv)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import aiohttp
import base64
import hashlib
import json
import os
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
    # 常用及核心地区
    "香港": "🇭🇰",
    "台湾": "🇹🇼",
    "美国": "🇺🇸",
    "英国": "🇬🇧",
    "韩国": "🇰🇷",
    "日本": "🇯🇵",
    "新加坡": "🇸🇬",
    "德国": "🇩🇪",
    "法国": "🇫🇷",
    "加拿大": "🇨🇦",
    
    # 针对你截图精准补充的地区
    "越南": "🇻🇳",
    "荷兰": "🇳🇱",
    "俄罗斯联邦": "🇷🇺",
    "俄罗斯": "🇷🇺",
    
    # 亚洲其它常见地区
    "马来西亚": "🇲🇾",
    "泰国": "🇹🇭",
    "菲律宾": "🇵🇭",
    "印度": "🇮🇳",
    "印度尼西亚": "🇮🇩",
    "柬埔寨": "🇰🇭",
    "澳门": "🇲🇴",
    "巴基斯坦": "🇵🇰",
    "哈萨克斯坦": "🇰🇿",
    
    # 欧洲其它常见地区
    "土耳其": "🇹🇷",
    "意大利": "🇮🇹",
    "西班牙": "🇪🇸",
    "瑞士": "🇨🇭",
    "瑞典": "🇸🇪",
    "波兰": "🇵🇱",
    "乌克兰": "🇺🇦",
    "爱尔兰": "🇮🇪",
    "奥地利": "🇦🇹",
    "芬兰": "🇫🇮",
    
    # 美洲与大洋洲地区
    "澳大利亚": "🇦🇺",
    "新西兰": "🇳🇿",
    "巴西": "🇧🇷",
    "阿根廷": "🇦🇷",
    "墨西哥": "🇲🇽",
    "智利": "🇨🇱",
    
    # 中东与非洲地区
    "阿联酋": "🇦🇪",
    "沙特阿拉伯": "🇸🇦",
    "以色列": "🇮🇱",
    "南非": "🇿🇦",
    "埃及": "🇪🇬"
}

REGION_RULES = [
    ("香港", r"hk|hongkong|香港|🇭🇰"),
    ("台湾", r"tw|taiwan|台湾|臺灣|台灣|中华民国|中華民國|🇹🇼|🇨🇳tw"),
    ("日本", r"jp|japan|日本|东京|東京|大阪|🇯🇵"),
    ("新加坡", r"sg|singapore|新加坡|星加坡|狮城|🇸🇬"),
    ("美国", r"us|unitedstates|美国|美國|美利坚|🇺🇸"),
    ("韩国", r"kr|korea|韩国|韓國|首尔|首爾|🇰🇷"),
    ("英国", r"uk|britain|gb|英国|英國|伦敦|倫敦|🇬🇧"),
    ("德国", r"de|germany|德国|德國|法兰克福|🇩🇪"),
    ("法国", r"fr|france|法国|法國|巴黎|🇫🇷"),
    ("加拿大", r"ca|canada|加拿大|🇨🇦"),
    ("越南", r"vn|vietnam|越南|🇻🇳"),
    ("荷兰", r"nl|netherlands|荷兰|荷蘭|阿姆斯特丹|🇳🇱"),
    ("俄罗斯", r"ru|russia|俄罗斯|俄羅斯|莫斯科|俄罗斯联邦|俄羅斯聯邦|🇷🇺"),
    ("澳大利亚", r"au|australia|澳洲|澳大利亚|澳大利亞|悉尼|🇦🇺"),
    ("中国", r"cn|china|中国|中國|内陆|內陸|回国|回國|广东|廣東|🇨🇳")
]

NOISE_WORDS = [
    "BGP",
    "IPLC",
    "IEPL",
    "VIP",
    "Premium",
    "高速",
    "专线",
    "节点",
]

IP_CACHE = {}


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
        return base64.b64decode(text).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def clean_name(name: str):
    text = urllib.parse.unquote(name or "")

    for word in NOISE_WORDS:
        text = text.replace(word, "")

    text = re.sub(r"\s+", " ", text).strip()

    return text or "未知节点"


async def query_country(session, server):

    if not server:
        return "🌍 其它地区"

    if server in IP_CACHE:
        return IP_CACHE[server]

    try:
        socket.gethostbyname(server)
    except Exception:
        return "🌍 其它地区"

    async with SEM:
        try:
            url = f"http://ip-api.com/json/{server}?lang=zh-CN"

            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:

                data = await resp.json()

                if data.get("status") == "success":

                    country = data.get("country", "其它地区")

                    emoji = EMOJI_MAP.get(
                        country,
                        "🌍"
                    )

                    result = f"{emoji} {country}"

                    IP_CACHE[server] = result

                    return result

        except Exception:
            pass

    return "🌍 其它地区"


async def get_final_label(session, server, remarks):

    text = clean_name(remarks).lower()

    for region, pattern in REGION_RULES:

        if re.search(pattern, text):
            return f"{EMOJI_MAP.get(region, '🌍')} {region}"

    return await query_country(session, server)


def validate(proxy):

    if not isinstance(proxy, dict):
        return False

    if not proxy.get("server"):
        return False

    if not proxy.get("port"):
        return False

    if proxy.get("type") in [
        "vmess",
        "vless",
        "tuic"
    ]:
        return bool(proxy.get("uuid"))

    if proxy.get("type") in [
        "trojan",
        "hysteria2"
    ]:
        return bool(proxy.get("password"))

    return True


class Parser:

    @staticmethod
    async def parse(session, link):

        try:

            if link.startswith("vmess://"):
                return await Parser.parse_vmess(session, link)

            if link.startswith("vless://"):
                return await Parser.parse_vless(session, link)

            if link.startswith("trojan://"):
                return await Parser.parse_trojan(session, link)

            if link.startswith("ss://"):
                return await Parser.parse_ss(session, link)

            if (
                link.startswith("hy2://")
                or
                link.startswith("hysteria2://")
            ):
                return await Parser.parse_hy2(session, link)

            if link.startswith("tuic://"):
                return await Parser.parse_tuic(session, link)

        except Exception:
            return None

        return None

    @staticmethod
    async def parse_vmess(session, link):

        link = link.replace(
            "vmess://vmess://",
            "vmess://"
        )

        raw = link[8:].split("#")[0]

        data = json.loads(
            safe_b64decode(raw)
        )

        server = data.get("add")

        label = await get_final_label(
            session,
            server,
            data.get("ps")
        )

        network = data.get("net", "tcp")

        proxy = {
            "name": label,
            "type": "vmess",
            "server": server,
            "port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("scy", "auto"),
            "network": network,
            "tls": str(data.get("tls")).lower() in ["tls", "1", "true"],
            "skip-cert-verify": True
        }

        host = (
            data.get("host")
            or
            data.get("sni")
            or
            server
        )

        if network == "ws":
            proxy["ws-opts"] = {
                "path": data.get("path", "/"),
                "headers": {
                    "Host": host
                }
            }

        if network == "grpc":
            proxy["grpc-opts"] = {
                "grpc-service-name": data.get("path", "")
            }

        return proxy

    @staticmethod
    async def parse_vless(session, link):

        u = urllib.parse.urlparse(link)

        q = dict(
            urllib.parse.parse_qsl(u.query)
        )

        label = await get_final_label(
            session,
            u.hostname,
            u.fragment
        )

        proxy = {
            "name": label,
            "type": "vless",
            "server": u.hostname,
            "port": int(u.port or 443),
            "uuid": u.username,
            "network": q.get("type", "tcp"),
            "tls": q.get("security") in [
                "tls",
                "reality"
            ],
            "servername": (
                q.get("sni")
                or
                u.hostname
            ),
            "client-fingerprint": q.get("fp", "chrome"),
            "skip-cert-verify": True
        }

        if q.get("security") == "reality":
            proxy["reality-opts"] = {
                "public-key": q.get("pbk", ""),
                "short-id": q.get("sid", "")
            }

        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": q.get("path", "/"),
                "headers": {
                    "Host": q.get("host", u.hostname)
                }
            }

        if proxy["network"] == "grpc":
            proxy["grpc-opts"] = {
                "grpc-service-name": q.get(
                    "serviceName",
                    ""
                )
            }

        return proxy

    @staticmethod
    async def parse_trojan(session, link):

        u = urllib.parse.urlparse(link)

        label = await get_final_label(
            session,
            u.hostname,
            u.fragment
        )

        return {
            "name": label,
            "type": "trojan",
            "server": u.hostname,
            "port": int(u.port or 443),
            "password": u.username,
            "sni": u.hostname,
            "skip-cert-verify": True
        }

    @staticmethod
    async def parse_ss(session, link):

        raw = link[5:].split("#")[0]

        if "@" not in raw:
            raw = safe_b64decode(raw)

        if "@" not in raw:
            return None

        auth, endpoint = raw.rsplit("@", 1)

        if ":" not in auth:
            auth = safe_b64decode(auth)

        if ":" not in auth:
            return None

        cipher, password = auth.split(":", 1)
    @staticmethod
    async def parse_ss(session, link):
        try:
            # 优先提取真正带有国家/数字编号信息的节点备注名
            remarks = "SS节点"
            if "#" in link:
                link, rem = link.split("#", 1)
                remarks = urllib.parse.unquote(rem.strip())

            # 此时 link 已经没有 # 符号了，安全截取协议头后面的核心数据
            raw = link[5:]
            if not raw:
                return None
            
            # 兼容老规范：如果整段不含 @，说明整体进行了 Base64 编码
            if "@" not in raw:
                try:
                    raw = safe_b64decode(raw)
                except Exception:
                    return None

            if not raw or "@" not in raw:
                return None

            # 从右往左切分，剥离出最后一处 @ 后面的地址部分，防止密码或用户名中包含 @ 符号
            parts = raw.rsplit("@", 1)
            if len(parts) < 2:
                return None
            auth, endpoint = parts[0], parts[1]

            # 兼容新规范(SIP002)：如果 auth 部分不含冒号，说明它是单独的 Base64 编码
            if ":" not in auth:
                try:
                    auth = safe_b64decode(auth)
                except Exception:
                    return None

            if not auth or ":" not in auth:
                return None

            # 密码部分可能包含冒号，因此只切分第一处冒号作为加密方式
            auth_parts = auth.split(":", 1)
            if len(auth_parts) < 2:
                return None
            cipher, password = auth_parts[0], auth_parts[1]

            # 核心清洗：移除 endpoint 可能附带的 query 或 path (如 ?plugin=...)
            if "?" in endpoint:
                endpoint = endpoint.split("?", 1)[0]
            if "/" in endpoint:
                endpoint = endpoint.split("/", 1)[0]

            # 解析 endpoint 端口与服务器（兼容 IPv6 格式）
            if endpoint.startswith("["):
                match = re.match(r"\[(.+)\]:(\d+)", endpoint)
                if not match:
                    return None
                server, port_str = match.group(1), match.group(2)
            else:
                endpoint_parts = endpoint.rsplit(":", 1)
                if len(endpoint_parts) < 2:
                    return None
                server, port_str = endpoint_parts[0], endpoint_parts[1]

            try:
                port = int(str(port_str).strip())
            except Exception:
                port = 8388
                
            if not server:
                return None

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
    async def parse_hy2(session, link):
        """全面标准支持 Hysteria 2 (Hy2) 协议（全防御加固版）"""
        try:
            if link.startswith("hy2://"):
                link = link.replace("hy2://", "hysteria2://", 1)

            u = urllib.parse.urlparse(link)
            # 核心修复：统一将 query 的键转为小写，防止因机场大小写不规范导致无法识别参数的 Bug
            q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query)}
            remarks = urllib.parse.unquote(u.fragment or "Hysteria2节点")
            
            hostname = u.hostname
            if not hostname:
                return None
            if hostname.startswith("[") and hostname.endswith("]"):
                hostname = hostname[1:-1]

            label = await get_final_label(session, hostname, remarks)

            # 核心修复：安全提取端口，防止直接访问 u.port 抛出 ValueError 导致丢节点
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
                "name": label,
                "type": "hysteria2",
                "server": hostname,
                "port": port,
                "password": u.username or "",
                "sni": q.get("sni") or hostname,
                "skip-cert-verify": True
            }
            
            if q.get("obfs"):
                proxy["obfs"] = q.get("obfs")
                if q.get("obfs-password"):
                    proxy["obfs-password"] = q.get("obfs-password")
                    
            return proxy
        except Exception:
            return None

    @staticmethod
    async def parse_tuic(session, link):
        """全面标准支持 TUIC v5 协议（彻底修复数据类型与赋值 Bug）"""
        try:
            u = urllib.parse.urlparse(link)
            q = {k.lower(): v for k, v in urllib.parse.parse_qsl(u.query)}
            remarks = urllib.parse.unquote(u.fragment or "TUIC节点")
            
            hostname = u.hostname
            if not hostname:
                return None
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

            # 核心修复：还原为安全的单字符串解析，拒绝输出 List 格式类型
            uuid_str = u.username or ""
            password_str = u.password or q.get("pass") or ""

            # 如果 urlparse 原生没解析出来，则通过 netloc 进行手工高容错切分
            if not uuid_str and u.netloc and "@" in u.netloc:
                user_info = u.netloc.rsplit("@", 1)[0]
                if ":" in user_info:
                    u_parts = user_info.split(":", 1)
                    uuid_str, password_str = u_parts[0], u_parts[1]
                else:
                    uuid_str = user_info

            if not uuid_str:
                return None

            return {
                "name": label,
                "type": "tuic",
                "server": hostname,
                "port": port,
                "uuid": str(uuid_str).strip(),
                "password": str(password_str).strip(),
                "alpn": [q.get("alpn", "h3")],
                "congestion-controller": q.get("congestion_control", "bbr"),
                "sni": q.get("sni") or hostname,
                "skip-cert-verify": True
            }
        except Exception:
            return None


async def build():

    load_cache()

    path = Path("nodes.txt")

    if not path.exists():
        print("nodes.txt not found")
        return

    links = []

    for line in path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines():

        line = line.strip()

        if line:
            links.append(line)

    region_map = defaultdict(list)

    clash_proxies = []

    rocket_links = []

    seen = set()

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=50
    )

    async with aiohttp.ClientSession(
        connector=connector
    ) as session:

        for link in links:

            proxy = await Parser.parse(
                session,
                link
            )

            if not proxy:
                continue

            fp = (
                proxy.get("server"),
                proxy.get("port"),
                proxy.get("type")
            )

            if fp in seen:
                continue

            seen.add(fp)

            label = proxy["name"]

            idx = (
                len(region_map[label])
                + 1
            )

            proxy["name"] = (
                f"{label} "
                f"{idx:02d} "
                f"{CHANNEL_MARK}"
            )

            if validate(proxy):

                clash_proxies.append(proxy)

                region_map[label].append(
                    proxy["name"]
                )

            rocket_links.append(
                f"{link.split('#')[0]}"
                f"#{urllib.parse.quote(proxy['name'])}"
            )

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
                "proxies": (
                    ["🎬 自动选择", "🎯 手动选择"]
                    +
                    list(region_map.keys())
                    +
                    ["DIRECT"]
                )
            },
            {
                "name": "🎬 自动选择",
                "type": "url-test",
                "url": TEST_URL,
                "interval": 300,
                "proxies": [
                    x["name"]
                    for x in clash_proxies
                ]
            },
            {
                "name": "🎯 手动选择",
                "type": "select",
                "proxies": [
                    x["name"]
                    for x in clash_proxies
                ]
            }
        ],
        "rules": [
            "MATCH,🚀 节点选择"
        ]
    }

    for region, proxies in region_map.items():

        if not proxies:
           continue
        
        config["proxy-groups"].append({
            "name": region,
            "type": "url-test",
            "url": TEST_URL,
            "interval": 300,
            "proxies": proxies
        })

    yaml_text = yaml.safe_dump(
        config,
        allow_unicode=True,
        sort_keys=False
    )

    atomic_write(
        CONFIG_FILE,
        yaml_text
    )

    sub = base64.b64encode(
        "\n".join(rocket_links).encode()
    ).decode()

    atomic_write(
        INDEX_FILE,
        sub
    )

    atomic_write(
        MANIFEST_FILE,
        json.dumps({
            "generated_at": int(time.time()),
            "node_count": len(clash_proxies),
            "hash": hashlib.sha256(
                yaml_text.encode()
            ).hexdigest()
        }, indent=2)
    )

    save_cache()

    print(
        f"Generated {len(clash_proxies)} nodes"
    )


if __name__ == "__main__":
    asyncio.run(build())
