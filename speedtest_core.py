import os
import re
import sys
import json
import time
import yaml
import subprocess
from concurrent.futures import ThreadPoolExecutor

MAX_WORKERS = 40
TIMEOUT = 4

def download_mihomo_core():
    """使用多冗余分发集群，直接下载单文件免解压二进制内核，100% 杜绝人机拦截与解压漏洞"""
    core_path = "./mihomo"
    if os.path.exists(core_path):
        return core_path
    
    print("正在通过高速集群加载轻量级免解压测速内核...")
    
    # 采用完全编译好的单文件 Linux-amd64 内核（免解压直接运行版）
    urls = [
        "https://ghproxy.com",
        "https://ghfast.top",
        "https://github.com"
    ]
    
    success = False
    for url in urls:
        try:
            if os.path.exists(core_path): os.remove(core_path)
            print(f"正在尝试抓取通道: {url}")
            
            # 使用虚拟机原生的高性能 wget 命令进行单文件抓取，-t 2 重试两次，-T 15 超时控制
            # 浏览器头 UA 混淆伪装注入，彻底穿透防火墙
            subprocess.run([
                "wget", "-q", "-O", core_path, 
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                "-t", "2", "-T", "15", url
            ], check=True)
            
            # 质量拦截检测：小于 5MB (5000000 字节) 绝对是拦截网页或干扰空文本，直接抛出异常切入下一条镜像
            if os.path.exists(core_path) and os.path.getsize(core_path) < 5000000:
                raise ValueError("抓取到人机验证拦截页面，并非合规内核二进制流")
                
            # 赋予 Linux 环境下最高级别的安全可执行权限
            os.chmod(core_path, 0o755)
            print("🎉 恭喜！免解压直接运行版内核通过分发集群加载成功！")
            success = True
            return core_path
        except Exception as err:
            print(f"当前节点加载失败: {err}，正在自动挂载后备镜像...")
            continue
            
    if not success:
        print("警告：高速网络管道遭到限制，正在唤醒系统最终防御级网络穿透链条 (curl-tunnel)...")
        for url in urls:
            try:
                if os.path.exists(core_path): os.remove(core_path)
                # 使用后备系统级 curl 进行单文件强行透传
                subprocess.run(["curl", "-L", "-A", "Mozilla/5.0", "--retry", "2", "-o", core_path, url], check=True)
                if os.path.exists(core_path) and os.path.getsize(core_path) > 5000000:
                    os.chmod(core_path, 0o755)
                    print("🎉 终极系统强力穿透管道加载核心成功！")
                    return core_path
            except:
                continue
                
        print("致命缺陷：由于 GitHub Action 虚拟机当前的宿主机公网 IP 遭到官方人机风控全面死锁，脚本终止。")
        sys.exit(1)

def run_test_on_single_node(node_index, node_name, local_socks_port):
    """探针：并发捕获 100% 精准的底层物理出口位置"""
    api_url = "http://ip-api.com"
    cmd = ["curl", "-s", "--socks5-hostname", f"127.0.0.1:{local_socks_port}", "--max-time", str(TIMEOUT), api_url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if data.get("status") == "success":
                country = data.get("country", "未知")
                country_code = data.get("countryCode", "").upper()
                
                emoji_map = {
                    "HK": "🇭🇰", "TW": "🇹🇼", "US": "🇺🇸", "GB": "🇬🇧", "KR": "🇰🇷", 
                    "JP": "🇯🇵", "SG": "🇸🇬", "VN": "🇻🇳", "DE": "🇩🇪", "FR": "🇫🇷", 
                    "RU": "🇷🇺", "CN": "🇨🇳", "CA": "🇨🇦", "IR": "🇮🇷", "NL": "🇳🇱", 
                    "TR": "🇹🇷", "IN": "🇮🇳", "MY": "🇲🇾", "PH": "🇵🇭", "TH": "🇹🇭"
                }
                emoji = emoji_map.get(country_code, "🌍")
                print(f"✅ 节点 [{node_name}] 测试成功 -> 真实出口: {emoji} {country}")
                return node_index, f"{emoji} {country}"
    except:
        pass
    print(f"❌ 节点 [{node_name}] 超时或不可用")
    return node_index, None

def start_speedtest_pipeline(valid_proxies):
    if not valid_proxies:
        print("没有可用的节点进行测速")
        return valid_proxies

    core_bin = download_mihomo_core()
    temp_proxies = []
    temp_groups = []
    base_port = 20000
    
    for idx, proxy in enumerate(valid_proxies):
        p_copy = proxy.copy()
        p_copy["name"] = f"test_node_{idx}"
        temp_proxies.append(p_copy)
        local_port = base_port + idx
        temp_groups.append({
            "name": f"group_{idx}",
            "type": "select",
            "proxies": [f"test_node_{idx}"],
            "port": local_port
        })
        
    temp_config = {
        "mode": "rule",
        "log-level": "silent",
        "proxies": temp_proxies,
        "proxy-groups": temp_groups,
        "rules": ["MATCH,DIRECT"]
    }
    
    with open("speedtest_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(temp_config, f, allow_unicode=True)
        
    print("正在启动后台测速隧道核心...")
    proc = subprocess.Popen([core_bin, "-f", "speedtest_clash.yaml"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    print(f"开始并行测速校准（最大线程数: {MAX_WORKERS}）...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for idx, p in enumerate(valid_proxies):
            task = executor.submit(run_test_on_single_node, idx, p.get("name", f"Node_{idx}"), base_port + idx)
            futures.append(task)
            
        for future in futures:
            idx, label = future.result()
            if label:
                results[idx] = label
                
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        
    if os.path.exists("speedtest_clash.yaml"): 
        os.remove("speedtest_clash.yaml")
    
    final_proxies = []
    for idx, p in enumerate(valid_proxies):
        if idx in results:
            real_label = results[idx]
            clean_num = re.sub(r'[^0-9]', '', p.get("name", ""))
            p["name"] = f"{real_label} {clean_num if clean_num else idx} @zmxooo"
            
            if "label" in p: del p["label"]
            if "raw_json" in p: del p["raw_json"]
            final_proxies.append(p)
            
    return final_proxies
