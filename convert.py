# ==================== 导出 ====================
    if rocket_links:
        sub_content = "\n".join(rocket_links)
        sub_b64 = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')

        with open('sub.txt', 'w', encoding='utf-8') as f:
            f.write(sub_b64)
        print(f"✅ 订阅文件已生成: sub.txt ({len(rocket_links)} 个节点)")

        # Clash 配置
        clash_config = {
            "proxies": clash_proxies,
            "proxy-groups": [
                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": [p["name"] for p in clash_proxies]
                }
            ],
            "rules": []
        }

        with open('clash.yaml', 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        print("✅ Clash 配置文件已生成: clash.yaml")

    # 统计
    print("\n📊 地区统计:")
    for region, nodes in sorted(region_map.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"   {region} → {len(nodes)} 个")


if __name__ == "__main__":
    main()
