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
    lines = []
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
                    lines.append(line)
                    continue

                if not RULE_PATTERN.match(stripped):
                    print(f"  ERROR: {filename}:{lineno} invalid rule: {stripped}", file=sys.stderr)
                    has_error = True
                    continue

                lines.append(line)
                file_rules += 1
                rule_count += 1

        lines.append(f"\n# ===== {filename} =====\n")
        print(f"  {filename}: {file_rules} rules")

    lines.append("\n# ===== FINAL =====\n")
    lines.append("FINAL,PROXY\n")

    output_path = os.path.join(BUILD_DIR, output_name)
    with open(output_path, "w", encoding="utf-8") as out:
        out.writelines(lines)

    print(f"build success -> {output_name} ({rule_count} rules)")

if has_error:
    print("build finished with errors", file=sys.stderr)
    sys.exit(1)

print("all builds completed successfully")
