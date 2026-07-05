import os
import re
import sys
import json
from collections import Counter

RULE_DIR = "rules"
BUILD_DIR = "build"

RULE_PATTERN = re.compile(r"^(DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|USER-AGENT),.+,(DIRECT|PROXY|REJECT)$")

profiles = {
    "main.conf": [
        "core.txt", "accelerate.txt", "ai.txt", "video.txt",
        "game.txt", "privacy.txt", "adblock.txt", "custom.txt",
    ],
    "lite.conf": [
        "core.txt", "accelerate.txt", "adblock.txt",
    ],
    "ai.conf": [
        "ai.txt",
    ],
}

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

URL_REWRITE = """[URL Rewrite]
^https://.*\\.taobao\\.com/.*\\?.*spm=.* 302
^https://.*\\.jd\\.com/.*\\?.*cu=.* 302
^https://.*\\.weibo\\.com/.*\\?.*luicode=.* 302
"""

has_error = False
global_domains = Counter()


def parse_rules(files):
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


def generate_shadowrocket(rules):
    lines = [
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32",
        "",
        DNS_CONFIG,
        "",
        URL_REWRITE,
        "",
        "[Rule]",
    ]
    lines.extend(rules)
    lines.extend(["FINAL,PROXY", "", "[MITM]"])
    return "\n".join(lines)


def generate_clash(rules):
    proxy_rules, direct_rules, reject_rules = [], [], []
    for rule in rules:
        parts = rule.split(",")
        rtype, domain, policy = parts[0], parts[1], parts[2]
        entry = f"  - {rtype},{domain}"
        if policy == "PROXY":
            proxy_rules.append(entry)
        elif policy == "DIRECT":
            direct_rules.append(entry)
        elif policy == "REJECT":
            reject_rules.append(entry)

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
        lines.extend(["  # 广告拦截 & 隐私保护"] + reject_rules + [""])
    if proxy_rules:
        lines.extend(["  # 海外服务"] + proxy_rules + [""])
    if direct_rules:
        lines.extend(["  # 国内直连"] + direct_rules + [""])
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines)


def generate_surge(rules):
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
        lines.append(f"{parts[0]},{parts[1]},{parts[2]}")
    lines.append("FINAL,PROXY")
    return "\n".join(lines)


def generate_v2ray(rules):
    domain_proxy, domain_direct, domain_reject = [], [], []
    for rule in rules:
        parts = rule.split(",")
        rtype, domain, policy = parts[0], parts[1], parts[2]
        if policy == "PROXY":
            domain_proxy.append(domain)
        elif policy == "DIRECT":
            domain_direct.append(domain)
        elif policy == "REJECT":
            domain_reject.append(domain)

    routing = {"domainStrategy": "IPIfNonMatch", "rules": []}
    if domain_reject:
        routing["rules"].append({
            "type": "field", "outboundTag": "block",
            "domain": [f"domain:{d}" for d in domain_reject]
        })
    if domain_direct:
        routing["rules"].append({
            "type": "field", "outboundTag": "direct",
            "domain": [f"domain:{d}" for d in domain_direct]
        })
    if domain_proxy:
        routing["rules"].append({
            "type": "field", "outboundTag": "proxy",
            "domain": [f"domain:{d}" for d in domain_proxy]
        })

    return json.dumps(routing, indent=2, ensure_ascii=False)


FORMATS = {
    ".conf": ("Shadowrocket", generate_shadowrocket),
    ".yaml": ("Clash", generate_clash),
    ".sgconf": ("Surge", generate_surge),
    ".json": ("V2Ray", generate_v2ray),
}


def build_profile(output_name, files):
    print(f"\n{'='*50}")
    print(f"Building: {output_name}")
    print(f"{'='*50}")

    rules, duplicates = parse_rules(files)

    if duplicates:
        print(f"\n  ⚠️  发现 {len(duplicates)} 条重复规则:")
        for filename, lineno, rule in duplicates:
            print(f"    {filename}:{lineno} -> {rule}")

    policy_count = Counter(rule.split(",")[-1] for rule in rules)
    print(f"\n  📊 规则统计:")
    print(f"    总计: {len(rules)} 条")
    for policy, count in sorted(policy_count.items()):
        print(f"    {policy}: {count} 条")

    if output_name.endswith(".conf"):
        for ext, (name, generator) in FORMATS.items():
            fname = output_name.replace(".conf", ext)
            content = generator(rules)
            fpath = os.path.join(BUILD_DIR, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  ✅ {name} -> {fpath}")

    return len(rules), len(duplicates)


def main():
    os.makedirs(BUILD_DIR, exist_ok=True)

    total_rules = 0
    total_duplicates = 0

    for output_name, files in profiles.items():
        rules, dups = build_profile(output_name, files)
        total_rules += rules
        total_duplicates += dups

    print(f"\n{'='*50}")
    print(f"📋 全局统计")
    print(f"{'='*50}")
    print(f"  总规则数: {total_rules}")
    print(f"  唯一域名: {len(global_domains)}")
    print(f"  重复规则: {total_duplicates}")

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
