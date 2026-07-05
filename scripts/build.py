import os
import re
import sys
from collections import Counter

RULE_DIR = "rules"
BUILD_DIR = "build"
DNS_BLOCKED = "127.0.0.1"

VALID_POLICIES = {"DIRECT", "PROXY", "REJECT"}
RULE_PATTERN = re.compile(r"^(DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|USER-AGENT),.+,(DIRECT|PROXY|REJECT)$")

profiles = {
    "main.conf": [
        "core.txt",
        "accelerate.txt",
        "ai.txt",
        "video.txt",
        "game.txt",
        "privacy.txt",
        "adblock.txt",
        "custom.txt",
    ],
    "lite.conf": [
        "core.txt",
        "accelerate.txt",
        "adblock.txt",
    ],
    "ai.conf": [
        "ai.txt",
    ],
}

# DNS 防污染配置
DNS_CONFIG = """[DNS]
server=223.5.5.5
server=119.29.29.29
server=8.8.8.8
server=1.1.1.1
server=/google.com/8.8.8.8
server=/openai.com/8.8.8.8
server=/anthropic.com/8.8.8.8
server=/claude.ai/8.8.8.8
server=/youtube.com/8.8.8.8
server=/github.com/8.8.8.8
server=/twitter.com/8.8.8.8
server=/x.com/8.8.8.8
server=/reddit.com/8.8.8.8
server=/spotify.com/8.8.8.8
server=/netflix.com/8.8.8.8
server=/twitch.tv/8.8.8.8
server=/discord.com/1.1.1.1
server=/telegram.org/8.8.8.8
server=/facebook.com/8.8.8.8
server=/instagram.com/8.8.8.8
server=/tiktok.com/8.8.8.8
server=/midjourney.com/8.8.8.8
server=/huggingface.co/1.1.1.1
server=/perplexity.ai/8.8.8.8
server=/notion.so/8.8.8.8
server=/slack.com/8.8.8.8
server=/zoom.us/8.8.8.8
server=/docker.io/1.1.1.1
server=/npmjs.com/1.1.1.1
server=/vercel.app/1.1.1.1
server=/netlify.app/1.1.1.1
server=/disneyplus.com/8.8.8.8
server=/hbomax.com/8.8.8.8
server=/hulu.com/8.8.8.8
server=/primevideo.com/8.8.8.8
server=/cursor.sh/8.8.8.8
server=/openrouter.ai/8.8.8.8
server=/poe.com/8.8.8.8
server=/groq.com/8.8.8.8
server=/cohere.com/8.8.8.8
server=/cloudflare.com/1.1.1.1
server=/gitlab.com/1.1.1.1
server=/copilot.microsoft.com/8.8.8.8
server=/bing.com/8.8.8.8
server=/steamcontent.com/8.8.8.8
server=/steampowered.com/8.8.8.8
server=/playstation.com/8.8.8.8
server=/nintendo.net/8.8.8.8
server=/xboxlive.com/8.8.8.8
"""

# URL Rewrite 去广告参数
URL_REWRITE = """[URL Rewrite]
# 去除电商追踪参数
^https://.*\\.taobao\\.com/.*\\?.*spm=.* 302
^https://.*\\.jd\\.com/.*\\?.*cu=.* 302
# 去除社交媒体追踪
^https://.*\\.weibo\\.com/.*\\?.*luicode=.* 302
"""

os.makedirs(BUILD_DIR, exist_ok=True)

has_error = False
global_domains = Counter()


def parse_rules(files):
    """解析规则文件，返回规则列表并检测重复"""
    rules = []
    seen = set()
    duplicates = []

    for filename in files:
        path = os.path.join(RULE_DIR, filename)

        if not os.path.exists(path):
            print(f"  WARNING: {filename} not found, skipping", file=sys.stderr)
            continue

        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                if not RULE_PATTERN.match(stripped):
                    print(f"  ERROR: {filename}:{lineno} invalid rule: {stripped}", file=sys.stderr)
                    global has_error
                    has_error = True
                    continue

                parts = stripped.split(",")
                key = (parts[0], parts[1])

                if key in seen:
                    duplicates.append((filename, lineno, stripped))
                else:
                    seen.add(key)
                    rules.append(stripped)
                    global_domains[parts[1]] += 1

    return rules, duplicates


def generate_shadowrocket(rules, dns=True, url_rewrite=True):
    """生成 Shadowrocket 格式"""
    lines = [
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32",
        "",
    ]

    if dns:
        lines.append(DNS_CONFIG)
        lines.append("")

    if url_rewrite:
        lines.append(URL_REWRITE)
        lines.append("")

    lines.append("[Rule]")
    lines.extend(rules)
    lines.append("FINAL,PROXY")
    lines.append("")
    lines.append("[MITM]")

    return "\n".join(lines)


def generate_clash(rules):
    """生成 Clash YAML 格式"""
    proxy_rules = []
    direct_rules = []
    reject_rules = []

    for rule in rules:
        parts = rule.split(",")
        rtype, domain, policy = parts[0], parts[1], parts[2]

        if policy == "PROXY":
            proxy_rules.append(f"  - {rtype.replace('DOMAIN-SUFFIX', 'DOMAIN-SUFFIX')},{domain}")
        elif policy == "DIRECT":
            direct_rules.append(f"  - {rtype.replace('DOMAIN-SUFFIX', 'DOMAIN-SUFFIX')},{domain}")
        elif policy == "REJECT":
            reject_rules.append(f"  - {rtype.replace('DOMAIN-SUFFIX', 'DOMAIN-SUFFIX')},{domain}")

    lines = [
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "",
        "dns:",
        "  enable: true",
        "  nameserver:",
        "    - 223.5.5.5",
        "    - 119.29.29.29",
        "  fallback:",
        "    - 8.8.8.8",
        "    - 1.1.1.1",
        "  fallback-filter:",
        "    geoip: true",
        "    ipcidr:",
        "      - 240.0.0.0/4",
        "",
        "proxy-groups:",
        "  - name: PROXY",
        "    type: select",
        "    proxies:",
        "      - DIRECT",
        "",
        "rules:",
    ]

    if reject_rules:
        lines.append("  # 广告拦截 & 隐私保护")
        lines.extend(reject_rules)
        lines.append("")

    if proxy_rules:
        lines.append("  # 海外服务")
        lines.extend(proxy_rules)
        lines.append("")

    if direct_rules:
        lines.append("  # 国内直连")
        lines.extend(direct_rules)
        lines.append("")

    lines.append("  - MATCH,PROXY")

    return "\n".join(lines)


def generate_surge(rules):
    """生成 Surge 配置格式"""
    lines = [
        "[General]",
        "loglevel = notify",
        "skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "exclude-simple-hostnames = true",
        "",
        "[Rule]",
    ]

    for rule in rules:
        parts = rule.split(",")
        rtype, domain, policy = parts[0], parts[1], parts[2]
        surge_type = rtype.replace("DOMAIN-SUFFIX", "DOMAIN-SUFFIX")
        lines.append(f"{surge_type},{domain},{policy}")

    lines.append("FINAL,PROXY")

    return "\n".join(lines)


def build_profile(output_name, files):
    """构建单个配置文件"""
    print(f"\n{'='*50}")
    print(f"Building: {output_name}")
    print(f"{'='*50}")

    rules, duplicates = parse_rules(files)

    # 报告重复
    if duplicates:
        print(f"\n  ⚠️  发现 {len(duplicates)} 条重复规则:")
        for filename, lineno, rule in duplicates:
            print(f"    {filename}:{lineno} -> {rule}")

    # 规则统计
    policy_count = Counter()
    for rule in rules:
        policy = rule.split(",")[-1]
        policy_count[policy] += 1

    print(f"\n  📊 规则统计:")
    print(f"    总计: {len(rules)} 条")
    for policy, count in sorted(policy_count.items()):
        print(f"    {policy}: {count} 条")

    # 生成 Shadowrocket 格式
    if output_name.endswith(".conf"):
        content = generate_shadowrocket(rules, dns=True, url_rewrite=True)
        output_path = os.path.join(BUILD_DIR, output_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✅ Shadowrocket -> {output_path}")

        # 生成 Clash 格式
        clash_name = output_name.replace(".conf", ".yaml")
        clash_content = generate_clash(rules)
        clash_path = os.path.join(BUILD_DIR, clash_name)
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write(clash_content)
        print(f"  ✅ Clash -> {clash_path}")

        # 生成 Surge 格式
        surge_name = output_name.replace(".conf", ".sgconf")
        surge_content = generate_surge(rules)
        surge_path = os.path.join(BUILD_DIR, surge_name)
        with open(surge_path, "w", encoding="utf-8") as f:
            f.write(surge_content)
        print(f"  ✅ Surge -> {surge_path}")

    return len(rules), len(duplicates)


def main():
    os.makedirs(BUILD_DIR, exist_ok=True)

    total_rules = 0
    total_duplicates = 0

    for output_name, files in profiles.items():
        rules, dups = build_profile(output_name, files)
        total_rules += rules
        total_duplicates += dups

    # 全局统计
    print(f"\n{'='*50}")
    print(f"📋 全局统计")
    print(f"{'='*50}")
    print(f"  总规则数: {total_rules}")
    print(f"  唯一域名: {len(global_domains)}")
    print(f"  重复规则: {total_duplicates}")

    # Top 10 重复域名
    most_common = global_domains.most_common(10)
    if most_common:
        print(f"\n  🔝 最常引用的域名:")
        for domain, count in most_common:
            if count > 1:
                print(f"    {domain}: {count} 次")

    if has_error:
        print(f"\n❌ 构建完成但存在错误", file=sys.stderr)
        sys.exit(1)

    print(f"\n✅ 所有构建完成")


if __name__ == "__main__":
    main()
