import os

RULE_DIR = "rules"
OUTPUT = "build/main.conf"

FILES = [
    "core.txt",
    "accelerate.txt",
    "adblock.txt",
    "custom.txt"
]

lines = []

for filename in FILES:

    path = os.path.join(RULE_DIR, filename)

    if not os.path.exists(path):
        continue

    lines.append(f"\n# ===== {filename} =====\n")

    with open(path, "r", encoding="utf-8") as f:
        lines.extend(f.readlines())

lines.append("\n# ===== FINAL =====\n")
lines.append("FINAL,PROXY\n")

os.makedirs("build", exist_ok=True)

with open(OUTPUT, "w", encoding="utf-8") as out:
    out.writelines(lines)

print("build success")
