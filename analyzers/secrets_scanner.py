import os
import re
import math
from typing import List, Dict


_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,20})?(secret|access)[\s:=\"']{0,5}([A-Za-z0-9/+=]{40})")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("private_key", re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")),
]


_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf",
    ".zip", ".gz", ".tgz", ".xz", ".7z", ".jar", ".exe", ".dll",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _looks_like_secret_candidate(token: str) -> bool:
    if len(token) < 20:
        return False
    if re.fullmatch(r"[A-Za-z0-9/_+=-]+", token) is None:
        return False
    return _shannon_entropy(token) >= 3.5


def _iter_text_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        # skip common large/noise dirs
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "dist", "build", "out"}]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _BINARY_EXTENSIONS:
                continue
            path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(path) > 1024 * 1024:  # 1MB cap
                    continue
            except OSError:
                continue
            yield path


def run_secrets_scan(path: str) -> Dict:
    print("🔑 Running secrets scan...")
    findings: List[Dict] = []

    for file_path in _iter_text_files(path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        # Regex-based detections
        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                findings.append({
                    "type": kind,
                    "file": file_path,
                    "match": match.group(0)[:8] + "…"
                })

        # Entropy-based heuristic on long tokens
        for candidate in re.findall(r"[A-Za-z0-9/_+=-]{20,}", content):
            if _looks_like_secret_candidate(candidate):
                findings.append({
                    "type": "high_entropy_token",
                    "file": file_path,
                    "match": candidate[:8] + "…"
                })

    # Simple scoring: 2 points if any hard secret; 1 if only entropy; cap 5
    hard_secret_types = {name for name, _ in _SECRET_PATTERNS}
    has_hard = any(f["type"] in hard_secret_types for f in findings)
    has_entropy_only = any(f["type"] == "high_entropy_token" for f in findings)

    score = 0
    if has_hard:
        score += 3
    if has_entropy_only:
        score += 1
    score = min(score, 5)

    print(f"🔎 Secrets findings: {len(findings)}")
    return {
        "score": score,
        "issues": findings,
    }


