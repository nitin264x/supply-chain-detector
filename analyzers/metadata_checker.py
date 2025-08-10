import json
import os


def run_metadata_check(path):
    print("📋 Checking metadata...")

    metadata_file = os.path.join(path, "package.json")
    if not os.path.exists(metadata_file):
        print("❌ No package.json found.")
        return {"score": 0, "issues": ["no_metadata"]}

    with open(metadata_file, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except:
            print("❌ Error reading package.json")
            return {"score": 1, "issues": ["invalid_json"]}

    score = 0
    issues = []

    # Check for suspicious dependencies
    dependencies = data.get("dependencies", {})
    if "child_process" in dependencies:
        score += 2
        issues.append("uses_child_process")

    if len(dependencies) > 10:
        score += 1
        issues.append("many_dependencies")

    # Check for weird version
    version = data.get("version", "")
    if version.startswith("5.") or version.startswith("0.0"):
        score += 1
        issues.append("suspicious_version")

    print(f"📦 Metadata issues: {issues}")
    return {"score": score, "issues": issues}
