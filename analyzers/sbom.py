import json
import os
from typing import Dict, List, Tuple


_DISALLOWED_LICENSES = {
    "GPL-3.0", "AGPL-3.0", "SSPL-1.0",
}


def _read_package_json(path: str) -> Dict:
    package_file = os.path.join(path, "package.json")
    if not os.path.exists(package_file):
        return {}
    try:
        with open(package_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _collect_dependencies(pkg: Dict) -> Dict[str, str]:
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        d = pkg.get(key, {})
        if isinstance(d, dict):
            deps.update({str(k): str(v) for k, v in d.items()})
    return deps


def _extract_license(pkg: Dict) -> str:
    lic = pkg.get("license")
    if isinstance(lic, str):
        return lic
    if isinstance(lic, dict):
        t = lic.get("type") or lic.get("name")
        if isinstance(t, str):
            return t
    return "UNKNOWN"


def generate_sbom(path: str) -> Dict:
    """Generate a simple SBOM-like structure for npm projects.

    Returns a dict with components, detected license, and policy issues.
    """
    print("📦 Generating SBOM...")
    pkg = _read_package_json(path)
    if not pkg:
        return {"components": [], "license": "UNKNOWN", "issues": ["no_package_json"], "score": 0}

    components = []
    deps = _collect_dependencies(pkg)
    for name, version in deps.items():
        components.append({
            "name": name,
            "version": version,
        })

    license_str = _extract_license(pkg)

    issues: List[str] = []
    score = 0

    # License policy
    if license_str in _DISALLOWED_LICENSES:
        issues.append(f"disallowed_license:{license_str}")
        score += 2
    elif license_str == "UNKNOWN":
        issues.append("unknown_license")
        score += 1

    # Heuristic: too many direct dependencies
    if len(deps) > 30:
        issues.append("many_dependencies_direct")
        score += 1

    # Cap score
    score = min(score, 5)

    return {
        "components": components,
        "license": license_str,
        "issues": issues,
        "score": score,
    }


