import os
import re
import sys

RULE_DIR = "rules"
BUILD_DIR = "build"

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

os.makedirs(BUILD_DIR, exist_ok=True)

has_error = False

for output_name, files in profiles.items():
    rules = []
    rule_count = 0

    for filename in files:
        path = os.path.join(RULE_DIR, filename)

        if not os.path.exists(path):
            print(f"  WARNING: {filename} not found, skipping", file=sys.stderr)
            continue

        file_rules = 0
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                if not RULE_PATTERN.match(stripped):
                    print(f"  ERROR: {filename}:{lineno} invalid rule: {stripped}", file=sys.stderr)
                    has_error = True
                    continue

                rules.append(stripped)
                file_rules += 1
                rule_count += 1

        print(f"  {filename}: {file_rules} rules")

    output_lines = [
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32",
        "",
        "[Rule]",
    ]

    output_lines.extend(rules)
    output_lines.append("FINAL,PROXY")

    output_path = os.path.join(BUILD_DIR, output_name)
    with open(output_path, "w", encoding="utf-8") as out:
        out.write("\n".join(output_lines) + "\n")

    print(f"build success -> {output_name} ({rule_count} rules)")

if has_error:
    print("build finished with errors", file=sys.stderr)
    sys.exit(1)

print("all builds completed successfully")
