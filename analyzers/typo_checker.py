import json
import os
from typing import Dict, List, Tuple


_POPULAR_PACKAGES = {
    "react", "lodash", "axios", "express", "vue", "next", "typescript",
    "webpack", "jest", "rxjs", "eslint", "prettier", "moment",
}


def _read_package_json(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[-1] + 1,        # insertion
                prev[j] + 1,          # deletion
                prev[j - 1] + cost,   # substitution
            ))
        prev = curr
    return prev[-1]


def _closest_popular_name(name: str) -> Tuple[str, int]:
    name = name.lower()
    best_pkg = ""
    best_dist = 999
    for pkg in _POPULAR_PACKAGES:
        d = _levenshtein(name, pkg)
        if d < best_dist:
            best_dist = d
            best_pkg = pkg
    return best_pkg, best_dist


def run_typo_and_maintainer_check(path: str) -> Dict:
    print("🔤 Checking for typosquatting and maintainer hygiene...")
    pkg_json_path = os.path.join(path, "package.json")
    pkg = _read_package_json(pkg_json_path)
    if not pkg:
        return {"score": 0, "issues": ["no_package_json"], "details": {}}

    issues: List[Dict] = []

    name = str(pkg.get("name", "")).strip()
    if name:
        close_to, dist = _closest_popular_name(name)
        if 0 < dist <= 2:
            issues.append({"type": "typosquat_suspected", "name": name, "close_to": close_to, "distance": dist})

    # Maintainer/repo hygiene signals
    if not pkg.get("repository"):
        issues.append({"type": "no_repository"})
    author = pkg.get("author")
    if not author:
        issues.append({"type": "no_author"})
    maintainers = pkg.get("maintainers")
    if isinstance(maintainers, list) and len(maintainers) == 0:
        issues.append({"type": "no_maintainers"})

    # Simple scoring rules
    score = 0
    if any(i.get("type") == "typosquat_suspected" for i in issues):
        score += 2
    if any(i.get("type") in {"no_repository", "no_author", "no_maintainers"} for i in issues):
        score += 1
    score = min(score, 5)

    return {
        "score": score,
        "issues": issues,
    }


