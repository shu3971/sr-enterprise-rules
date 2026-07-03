import os

RULE_DIR = "rules"
BUILD_DIR = "build"

profiles = {
    "main.conf": [
        "core.txt",
        "accelerate.txt",
        "ai.txt",
        "video.txt",
        "game.txt",
        "privacy.txt",
        "adblock.txt",
        "custom.txt"
    ],

    "lite.conf": [
        "core.txt",
        "accelerate.txt",
        "adblock.txt"
    ],

    "ai.conf": [
        "ai.txt"
    ]
}

os.makedirs(BUILD_DIR, exist_ok=True)

for output_name, files in profiles.items():

    lines = []

    for filename in files:

        path = os.path.join(RULE_DIR, filename)

        if not os.path.exists(path):
            continue

        lines.append(f"\n# ===== {filename} =====\n")

        with open(path, "r", encoding="utf-8") as f:
            lines.extend(f.readlines())

    lines.append("\n# ===== FINAL =====\n")
    lines.append("FINAL,PROXY\n")

    output_path = os.path.join(BUILD_DIR, output_name)

    with open(output_path, "w", encoding="utf-8") as out:
        out.writelines(lines)

    print(f"build success -> {output_name}")
