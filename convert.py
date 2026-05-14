import base64
import json
import urllib.parse
import os
import re
import requests
import time
import yaml
from collections import defaultdict

# 频道水印
CHANNEL_MARK = "@zmxooo"

# ==================== 配置 ====================

IP_CACHE = {}

EMOJI_MAP = {
    "香港": "🇭🇰",
    "台湾": "🇹🇼",
    "美国": "🇺🇸",
    "英国": "🇬🇧",
    "韩国": "🇰🇷",
    "日本": "🇯🇵",
    "新加坡": "🇸🇬",
    "越南": "🇻🇳",
    "德国": "🇩🇪",
    "立陶宛": "🇱🇹",
    "法国": "🇫🇷",
    "俄罗斯": "🇷🇺",
    "加拿大": "🇨🇦",
    "荷兰": "🇳🇱",
    "澳大利亚": "🇦🇺",
    "阿联酋": "🇦🇪",
    "土耳其": "🇹🇷",
}


# ==================== Base64 ====================

def parse_vmess_b64(b64_part):

    if not isinstance(b64_part, str):
        b64_part = str(b64_part)

    b64_part = re.sub(
        r'[^a-zA-Z0-9+/=_-]',
        '',
        b64_part
    )

    b64_part = (
        b64_part
        .replace('-', '+')
        .replace('_', '/')
    )

    padding = len(b64_part) % 4

    if padding:
        b64_part += "=" * (4 - padding)

    try:
        return base64.b64decode(b64_part)

    except:
        return b""


# ==================== 安全转换 ====================

def safe_split(
        text: str,
        sep: str,
        default_val: str = "auto"
):

    if not text:
        return [default_val, ""]

    if sep in text:

        parts = text.split(sep, 1)

        return (
            parts
            if len(parts) == 2
            else [parts[0], ""]
        )

    return [str(text), ""]


def safe_int(val, default=443):

    try:

        if isinstance(val, int):
            return val

        clean_val = re.sub(
            r'\D',
            '',
            str(val)
        )

        return (
            int(clean_val)
            if clean_val
            else default
        )

    except:
        return default


# ==================== 清理 URI ====================

def clean_base_uri(link: str):

    parsed = urllib.parse.urlparse(link)

    return urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            parsed.query,
            ""
        )
    )


# ==================== 国家标签 ====================

def get_final_label(
        server: str,
        remarks: str = ""
):

    text = urllib.parse.unquote(
        str(remarks)
    ).lower()

    meta = [
        ("香港", r"hk|hongkong|香港"),
        ("台湾", r"tw|taiwan|台灣|台湾"),
        ("美国", r"us|unitedstates|美国|美國"),
        ("英国", r"gb|uk|britain|英国|英國"),
        ("韩国", r"kr|korea|韩国|韓國"),
        ("日本", r"jp|japan|日本"),
        ("新加坡", r"sg|singapore|新加坡"),
        ("德国", r"de|germany|德国"),
        ("立陶宛", r"lt|lithuania|立陶宛"),
    ]

    for name, pattern in meta:

        if re.search(pattern, text):

            return (
                f"{EMOJI_MAP.get(name, '🌍')} "
                f"{name}"
            )

    if server and re.match(
            r'^\d{1,3}(\.\d{1,3}){3}$',
            server
    ):

        if server in IP_CACHE:
            return IP_CACHE[server]

        try:

            time.sleep(0.05)

            resp = requests.get(
                f"http://ip-api.com/json/{server}?lang=zh-CN",
                timeout=3
            )

            data = resp.json()

            if data.get("status") == "success":

                country = data.get("country")

                label = (
                    f"{EMOJI_MAP.get(country, '🌍')} "
                    f"{country}"
                )

                IP_CACHE[server] = label

                return label

        except:
            pass

    return "🧿 其他地区"


# ==================== 协议解析 ====================

def parse_link(link: str):

    try:

        link = link.strip()

        if (
                not link
                or link.startswith((
                    'import',
                    'def',
                    '#',
                    'git'
                ))
        ):
            return None

        clean_link_str = link.split('#')[0]

        # ==================== Hysteria ====================

        if any(link.startswith(p) for p in [
            'hysteria://',
            'hysteria2://',
            'hy2://'
        ]):

            u = urllib.parse.urlparse(link)

            p_type = (
                "hysteria2"
                if "2" in link or "hy2" in link
                else "hysteria"
            )

            q = urllib.parse.parse_qs(
                u.query
            )

            raw_sni = q.get(
                "sni",
                [u.hostname]
            )[0]

            raw_sni = urllib.parse.unquote(
                raw_sni
            )

            if "://" in raw_sni:

                raw_sni = (
                    raw_sni
                    .split("://")[-1]
                    .split("/")[0]
                )

            return {
                "label": get_final_label(
                    u.hostname,
                    u.fragment
                ),
                "type": p_type,
                "server": (
                    u.hostname
                    if u.hostname
                    else "127.0.0.1"
                ),
                "port": (
                    int(u.port)
                    if u.port
                    else 443
                ),
                "password": (
                    urllib.parse.unquote(
                        u.username
                    )
                    if u.username
                    else ""
                ),
                "auth": (
                    urllib.parse.unquote(
                        u.username
                    )
                    if u.username
                    else ""
                ),
                "sni": raw_sni,
                "skip-cert-verify": True,
                "raw_link": link
            }

        # ==================== VMESS ====================

        elif link.startswith('vmess://'):

            b64_part = (
                link[8:]
                .split('#')[0]
            )

            raw_data = parse_vmess_b64(
                b64_part
            )

            if not raw_data:
                return None

            data = json.loads(
                raw_data.decode(
                    'utf-8',
                    'ignore'
                )
            )

            return {
                "type": "vmess",
                "raw_data": data,
                "server": data.get("add"),
                "original_remarks": data.get(
                    "ps",
                    ""
                )
            }

        # ==================== 其他协议 ====================

        elif link.startswith((
                'ss://',
                'trojan://',
                'vless://'
        )):

            u = urllib.parse.urlparse(
                clean_link_str
            )

            orig_remarks = ""

            if '#' in link:
                orig_remarks = link.split('#')[1]

            return {
                "type": u.scheme,
                "link_str": clean_link_str,
                "url_obj": u,
                "server": u.hostname,
                "original_remarks": orig_remarks
            }

    except:
        return None

    return None


# ==================== 主程序 ====================

def main():

    if not os.path.exists('nodes.txt'):

        print("❌ 未找到 nodes.txt 文件")

        return

    with open(
            'nodes.txt',
            'r',
            encoding='utf-8',
            errors='ignore'
    ) as f:

        lines = [
            line.strip()
            for line in f
            if line.strip()
        ]

    # ==================== 去重 ====================

    seen = set()

    unique_links = []

    for line in lines:

        core = clean_base_uri(line)

        if core not in seen:

            seen.add(core)

            unique_links.append(line)

    region_map = defaultdict(list)

    clash_proxies = []

    rocket_links = []

    print(
        f"🔄 正在处理去重后的 "
        f"{len(unique_links)} 个节点..."
    )

    # ==================== 节点处理 ====================

    for link in unique_links:

        p = parse_link(link)

        if not p or not p.get("server"):
            continue

        # 地区标签

        if "label" in p:

            label = p["label"]

        else:

            label = get_final_label(
                p.get("server"),
                p.get(
                    "original_remarks",
                    ""
                )
            )

        idx = len(region_map[label]) + 1

        new_name = (
            f"{label} "
            f"{idx:02d} "
            f"{CHANNEL_MARK}"
        )

        region_map[label].append(new_name)

        # ==================== VMESS ====================

        if p["type"] == "vmess":

            try:

                data = p["raw_data"].copy()

                data['ps'] = new_name

                new_json = json.dumps(
                    data,
                    separators=(',', ':')
                ).encode('utf-8')

                new_b64 = base64.b64encode(
                    new_json
                ).decode('utf-8')

                rocket_links.append(
                    f"vmess://{new_b64}"
                )

                network = data.get(
                    "net",
                    "tcp"
                )

                vmess_node = {
                    "name": new_name,
                    "type": "vmess",
                    "server": data.get(
                        "add",
                        "127.0.0.1"
                    ),
                    "port": safe_int(
                        data.get("port"),
                        443
                    ),
                    "uuid": data.get("id"),
                    "alterId": safe_int(
                        data.get("aid"),
                        0
                    ),
                    "cipher": "auto",
                    "tls": str(
                        data.get(
                            "tls",
                            ""
                        )
                    ).lower() in [
                        "tls",
                        "1",
                        "true"
                    ],
                    "udp": True,
                    "skip-cert-verify": True,
                    "network": network
                }

                host = data.get("host", "")

                path = data.get("path", "/")

                if host:
                    vmess_node["servername"] = host

                if network == "ws":

                    vmess_node["ws-opts"] = {
                        "path": path,
                        "headers": {
                            "Host": host
                        }
                    }

                elif network == "grpc":

                    vmess_node["grpc-opts"] = {
                        "grpc-service-name": path
                    }

                elif network == "h2":

                    vmess_node["h2-opts"] = {
                        "host": (
                            [host]
                            if host
                            else []
                        ),
                        "path": path
                    }

                clash_proxies.append(vmess_node)

            except:
                continue

        # ==================== 修复版 Hysteria ====================

        elif p["type"] in [
            "hysteria",
            "hysteria2"
        ]:

            # 不重建 URI
            # 保留机场原始参数

            parsed_url = urllib.parse.urlparse(
                link
            )

            base_uri = urllib.parse.urlunparse(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    "",
                    parsed_url.query,
                    ""
                )
            )

            rocket_links.append(
                f"{base_uri}"
                f"#{urllib.parse.quote(new_name)}"
            )

            clash_node = {
                "name": new_name,
                "type": p["type"],
                "server": p["server"],
                "port": p["port"],
                "sni": p["sni"],
                "skip-cert-verify": True,
                "alpn": ["h3"]
            }

            # Hysteria1

            if p["type"] == "hysteria":

                clash_node["auth-str"] = (
                    p["auth"]
                    if p.get("auth")
                    else p.get(
                        "password",
                        ""
                    )
                )

            # Hysteria2

            else:

                clash_node["password"] = (
                    p["password"]
                    if p.get("password")
                    else p.get(
                        "auth",
                        ""
                    )
                )

            clash_proxies.append(clash_node)

        # ==================== 其他协议 ====================

        else:

            u = p["url_obj"]

            qs = urllib.parse.parse_qs(
                u.query
            )

            params = {}

            for k, v in qs.items():

                if (
                        v
                        and isinstance(v, list)
                ):
                    params[k] = str(v[0])

                elif v:
                    params[k] = str(v)

            base_uri = clean_base_uri(link)

            rocket_links.append(
                f"{base_uri}"
                f"#{urllib.parse.quote(new_name)}"
            )

            proxy_cfg = {
                "name": new_name,
                "type": p["type"],
                "server": (
                    u.hostname
                    if u.hostname
                    else "127.0.0.1"
                ),
                "port": safe_int(
                    u.port,
                    443
                )
            }

            try:

                # ==================== SS ====================

                if p["type"] == "ss":

                    if '@' in u.netloc:

                        userinfo, _ = safe_split(
                            u.netloc,
                            '@'
                        )

                        if ':' in userinfo:

                            method, password = (
                                safe_split(
                                    userinfo,
                                    ':',
                                    'auto'
                                )
                            )

                        else:

                            decoded_ui = (
                                parse_vmess_b64(
                                    userinfo
                                )
                                .decode(
                                    'utf-8',
                                    'ignore'
                                )
                            )

                            method, password = (
                                safe_split(
                                    decoded_ui,
                                    ':',
                                    'auto'
                                )
                            )

                    else:

                        netloc_clean = (
                            u.netloc
                            .split('#')[0]
                        )

                        decoded_ui = (
                            parse_vmess_b64(
                                netloc_clean
                            )
                            .decode(
                                'utf-8',
                                'ignore'
                            )
                        )

                        if '@' in decoded_ui:

                            userinfo, hostinfo = (
                                safe_split(
                                    decoded_ui,
                                    '@'
                                )
                            )

                            method, password = (
                                safe_split(
                                    userinfo,
                                    ':',
                                    'auto'
                                )
                            )

                            if ':' in hostinfo:

                                s_host, s_port = (
                                    safe_split(
                                        hostinfo,
                                        ':'
                                    )
                                )

                                proxy_cfg[
                                    "server"
                                ] = s_host

                                proxy_cfg[
                                    "port"
                                ] = safe_int(
                                    s_port,
                                    443
                                )

                            else:

                                proxy_cfg[
                                    "server"
                                ] = hostinfo

                        else:
                            continue

                    proxy_cfg.update({
                        "cipher": method,
                        "password": password,
                        "udp": True
                    })

                    clash_proxies.append(
                        proxy_cfg
                    )

                # ==================== TROJAN ====================

                elif p["type"] == "trojan":

                    proxy_cfg.update({
                        "password": (
                            u.username
                            if u.username
                            else ""
                        ),
                        "udp": True,
                        "sni": params.get(
                            "sni",
                            u.hostname
                        ),
                        "skip-cert-verify": True
                    })

                    clash_proxies.append(
                        proxy_cfg
                    )

                # ==================== VLESS ====================

                elif p["type"] == "vless":

                    proxy_cfg.update({
                        "uuid": (
                            u.username
                            if u.username
                            else ""
                        ),
                        "cipher": "auto",
                        "udp": True,
                        "tls": (
                            params.get(
                                "security"
                            )
                            in [
                                "tls",
                                "reality"
                            ]
                        ),
                        "skip-cert-verify": True,
                        "network": params.get(
                            "type",
                            "tcp"
                        )
                    })

                    if params.get("sni"):

                        proxy_cfg[
                            "servername"
                        ] = params.get("sni")

                    if (
                            params.get("type")
                            == "ws"
                    ):

                        proxy_cfg[
                            "ws-opts"
                        ] = {
                            "path": params.get(
                                "path",
                                "/"
                            ),
                            "headers": {
                                "Host": params.get(
                                    "host",
                                    ""
                                )
                            }
                        }

                    if (
                            params.get("security")
                            == "reality"
                    ):

                        proxy_cfg[
                            "reality-opts"
                        ] = {
                            "public-key": params.get(
                                "pbk",
                                ""
                            ),
                            "short-id": params.get(
                                "sid",
                                ""
                            )
                        }

                        proxy_cfg[
                            "client-fingerprint"
                        ] = params.get(
                            "fp",
                            "chrome"
                        )

                    clash_proxies.append(
                        proxy_cfg
                    )

            except:
                continue

    # ==================== 输出 ====================

    try:

        raw_subscription_text = '\n'.join(
            rocket_links
        )

        b64_subscription_data = (
            base64.b64encode(
                raw_subscription_text.encode(
                    'utf-8'
                )
            ).decode('utf-8')
        )

        with open(
                'rocket_output.txt',
                'w',
                encoding='utf-8'
        ) as f:

            f.write(
                b64_subscription_data
            )

        with open(
                'clash_output.yaml',
                'w',
                encoding='utf-8'
        ) as f:

            yaml.dump(
                {
                    "proxies": clash_proxies
                },
                f,
                allow_unicode=True,
                sort_keys=False
            )

        print(
            "✅ 修复完成！"
        )

        print(
            f"✅ Clash 节点数量: "
            f"{len(clash_proxies)}"
        )

        print(
            f"✅ Rocket 节点数量: "
            f"{len(rocket_links)}"
        )

        print(
            "✅ 已输出 clash_output.yaml"
        )

        print(
            "✅ 已输出 rocket_output.txt"
        )

        print(
            "✅ HY2 Base64 已兼容小火箭"
        )

    except Exception as e:

        print(
            f"❌ 导出文件失败: {e}"
        )


# ==================== 入口 ====================

if __name__ == "__main__":
    main()
