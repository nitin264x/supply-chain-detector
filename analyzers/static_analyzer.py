import subprocess


def run_static_analysis(path):
    print("📦 Running static code analysis...")

    result = subprocess.run(
        ["semgrep", "--config", "auto", path],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='ignore'

    )

    findings = result.stdout.count("rule_id")  # count Semgrep matches
    score = min(findings, 5)  # keep the score simple: max 5

    print(f"🔍 Issues found: {findings}")
    return {"score": score, 
            "details": result.stdout,
            "score": 0,
            "issues": []
            }
