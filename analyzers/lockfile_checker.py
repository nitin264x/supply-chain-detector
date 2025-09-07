import json
import os
import re
from typing import Dict, List


SUSPICIOUS_SCRIPT_KEYS = {
    "preinstall", "install", "postinstall", "preuninstall", "postuninstall",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    ("curl_download", re.compile(r"\bcurl\b", re.I)),
    ("wget_download", re.compile(r"\bwget\b", re.I)),
    ("powershell_exec", re.compile(r"\bpowershell\b", re.I)),
    ("bash_exec", re.compile(r"\bbash\b|\bsh\b", re.I)),
    ("node_eval", re.compile(r"node\s+-e\s+")),
    ("chmod_exec", re.compile(r"\bchmod\s+\+x\b", re.I)),
    ("base64_eval", re.compile(r"base64\s+-d|atob\(", re.I)),
    ("tar_exec", re.compile(r"\btar\b", re.I)),
]


def _read_json(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _check_scripts(pkg: Dict) -> List[Dict]:
    findings: List[Dict] = []
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings
    for key, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue
        if key in SUSPICIOUS_SCRIPT_KEYS:
            findings.append({"type": "lifecycle_script", "script": key, "command": cmd})
        for ftype, pattern in SUSPICIOUS_COMMAND_PATTERNS:
            if pattern.search(cmd):
                findings.append({"type": f"script_{ftype}", "script": key, "command": cmd})
    return findings


def _check_lockfile(lock: Dict) -> List[Dict]:
    findings: List[Dict] = []
    if not lock:
        findings.append({"type": "no_lockfile"})
        return findings

    # npm v2 and v3 lock formats
    packages = lock.get("packages")
    if isinstance(packages, dict):
        for name, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            resolved = meta.get("resolved", "")
            integrity = meta.get("integrity")
            if isinstance(resolved, str):
                low = resolved.lower()
                if low.startswith("git+") or low.startswith("git://") or low.startswith("ssh://"):
                    findings.append({"type": "git_dependency", "package": name, "resolved": resolved})
                if low.startswith("http://") or low.startswith("https://") and ".tgz" not in low:
                    findings.append({"type": "url_dependency", "package": name, "resolved": resolved})
            if integrity is None:
                findings.append({"type": "missing_integrity", "package": name})
        return findings

    # npm v1: dependencies tree under dependencies
    def walk_deps(tree: Dict, prefix: str = ""):
        for pkg, meta in tree.items():
            if not isinstance(meta, dict):
                continue
            resolved = meta.get("resolved", "")
            integrity = meta.get("integrity")
            name = f"{prefix}{pkg}"
            if isinstance(resolved, str):
                low = resolved.lower()
                if low.startswith("git+") or low.startswith("git://") or low.startswith("ssh://"):
                    findings.append({"type": "git_dependency", "package": name, "resolved": resolved})
                if low.startswith("http://") or low.startswith("https://") and ".tgz" not in low:
                    findings.append({"type": "url_dependency", "package": name, "resolved": resolved})
            if integrity is None:
                findings.append({"type": "missing_integrity", "package": name})
            deps = meta.get("dependencies", {})
            if isinstance(deps, dict):
                walk_deps(deps, prefix=name+"/")
    deps_root = lock.get("dependencies")
    if isinstance(deps_root, dict):
        walk_deps(deps_root)

    return findings


def run_lockfile_and_scripts_check(path: str) -> Dict:
    print("📄 Checking lockfile and scripts...")
    pkg = _read_json(os.path.join(path, "package.json"))
    scripts_findings = _check_scripts(pkg) if pkg else []

    lockfile_path = None
    for candidate in ["package-lock.json", "npm-shrinkwrap.json"]:
        p = os.path.join(path, candidate)
        if os.path.exists(p):
            lockfile_path = p
            break
    lock = _read_json(lockfile_path) if lockfile_path else {}
    lock_findings = _check_lockfile(lock)

    findings = scripts_findings + lock_findings

    # Scoring: lifecycle/dangerous scripts +2, git/url deps +1, missing integrity +1, no lockfile +1 (cap 5)
    score = 0
    if any(f["type"] in {"lifecycle_script", "script_curl_download", "script_wget_download", "script_powershell_exec", "script_bash_exec", "script_node_eval", "script_base64_eval"} for f in findings):
        score += 2
    if any(f["type"] in {"git_dependency", "url_dependency"} for f in findings):
        score += 1
    if any(f["type"] == "missing_integrity" for f in findings):
        score += 1
    if any(f["type"] == "no_lockfile" for f in findings):
        score += 1
    score = min(score, 5)

    return {
        "score": score,
        "issues": findings,
    }


