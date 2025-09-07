import os
import json
from datetime import datetime


def write_report(static_result, metadata_result, total_score, package_path, sig_result=None, secrets_result=None, sbom_result=None, lockfile_result=None, typo_result=None, format: str = "md"):
    """
    Writes a markdown report for the scan results.
    static_result: dict from static analyzer
    metadata_result: dict from metadata checker
    total_score: int, combined score
    package_path: str, path or name of the scanned package
    sig_result: dict from signature_checker (optional)
    """
    
    # Create reports folder if it doesn't exist
    report_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(report_dir, exist_ok=True)

    # Normalize package path for filename safety
    safe_package_name = os.path.basename(os.path.normpath(package_path))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"{safe_package_name}_{timestamp}"
    report_md_path = os.path.join(report_dir, f"{base_filename}.md")
    report_json_path = os.path.join(report_dir, f"{base_filename}.json")

    report_lines = []
    report_lines.append(f"# 📦 Supply Chain Risk Report for `{package_path}`\n")
    
    # Static Analysis Section
    report_lines.append("## 🧮 Static Analysis")
    report_lines.append(f"**Static Score:** {static_result.get('score', 0)}")
    issues = static_result.get("issues", [])
    report_lines.append(f"**Issues Found:** {', '.join(issues) if issues else 'None'}")
    report_lines.append("")

    # Metadata Analysis Section
    report_lines.append("## 📋 Metadata Analysis")
    report_lines.append(f"**Metadata Score:** {metadata_result.get('score', 0)}")
    meta_issues = metadata_result.get("issues", [])
    report_lines.append(f"**Issues Found:** {', '.join(meta_issues) if meta_issues else 'None'}")
    report_lines.append("")

    # Secrets Scan Section (Addon)
    report_lines.append("## 🔑 Secrets Scan")
    if secrets_result is None:
        report_lines.append("ℹ️ Secrets scan not run.")
    else:
        report_lines.append(f"**Secrets Score:** {secrets_result.get('score', 0)}")
        secrets_issues = secrets_result.get("issues", [])
        if secrets_issues:
            # Show a compact list of types and counts
            type_counts = {}
            for f in secrets_issues:
                t = f.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            summary = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
            report_lines.append(f"**Findings:** {summary}")
        else:
            report_lines.append("**Findings:** None")
    report_lines.append("")

    # SBOM & License Section (Addon)
    report_lines.append("## 🧾 SBOM & License")
    if sbom_result is None:
        report_lines.append("ℹ️ SBOM not generated.")
    else:
        report_lines.append(f"**Declared License:** {sbom_result.get('license', 'UNKNOWN')}")
        sbom_issues = sbom_result.get("issues", [])
        report_lines.append(f"**Issues:** {', '.join(sbom_issues) if sbom_issues else 'None'}")
        components = sbom_result.get("components", [])
        report_lines.append(f"**Direct Dependencies:** {len(components)}")
    report_lines.append("")

    # Lockfile & Scripts Section (Addon)
    report_lines.append("## 📄 Lockfile & Scripts")
    if lockfile_result is None:
        report_lines.append("ℹ️ Lockfile/scripts check not run.")
    else:
        report_lines.append(f"**Lockfile/Scripts Score:** {lockfile_result.get('score', 0)}")
        lf_issues = lockfile_result.get("issues", [])
        if lf_issues:
            # Summarize by type counts
            type_counts = {}
            for f in lf_issues:
                t = f.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            summary = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
            report_lines.append(f"**Findings:** {summary}")
        else:
            report_lines.append("**Findings:** None")
    report_lines.append("")

    # Typosquatting & Maintainer Section (Addon)
    report_lines.append("## 🔤 Typosquatting & Maintainers")
    if typo_result is None:
        report_lines.append("ℹ️ Typosquatting/maintainer check not run.")
    else:
        report_lines.append(f"**Typo/Maintainer Score:** {typo_result.get('score', 0)}")
        t_issues = typo_result.get("issues", [])
        if t_issues:
            type_counts = {}
            for f in t_issues:
                t = f.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            summary = ", ".join(f"{k}: {v}" for k, v in type_counts.items())
            report_lines.append(f"**Findings:** {summary}")
        else:
            report_lines.append("**Findings:** None")
    report_lines.append("")

    # Signature Verification Section (Week 3)
    report_lines.append("## 🔐 Signature Verification")
    if sig_result is None:
        report_lines.append("ℹ️ Signature verification not applicable.")
    elif sig_result.get("verified") is True:
        report_lines.append("✅ Package is signed and verified.")
    elif sig_result.get("verified") is False:
        report_lines.append("❌ Package signature verification failed or not found.")
    else:
        report_lines.append(f"ℹ️ Signature check could not be completed. Details: {sig_result}")
    report_lines.append("")

    # Final Score & Risk
    report_lines.append("## 📊 Final Risk Assessment")
    report_lines.append(f"**Final Risk Score:** {total_score}")
    if total_score >= 7:
        risk_level = "🚨 HIGH"
    elif total_score >= 4:
        risk_level = "⚠️ MEDIUM"
    else:
        risk_level = "✅ LOW"
    report_lines.append(f"**RISK LEVEL:** {risk_level}")
    report_lines.append("")

    saved_paths = []

    # Save markdown if requested
    if format in ("md", "both"):
        with open(report_md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        saved_paths.append(report_md_path)

    # Save JSON if requested
    if format in ("json", "both"):
        json_payload = {
            "target": package_path,
            "scores": {
                "static": static_result.get("score", 0),
                "metadata": metadata_result.get("score", 0),
                "total": total_score,
            },
            "findings": {
                "static": static_result.get("issues", []),
                "metadata": metadata_result.get("issues", []),
                "secrets": (secrets_result.get("issues", []) if secrets_result else []),
                "sbom": (sbom_result.get("issues", []) if sbom_result else []),
                "lockfile": (lockfile_result.get("issues", []) if lockfile_result else []),
                "typo": (typo_result.get("issues", []) if typo_result else []),
            },
            "sbom": {
                "license": (sbom_result.get("license") if sbom_result else None),
                "components_count": (len(sbom_result.get("components", [])) if sbom_result else 0),
                "components": (sbom_result.get("components", []) if sbom_result else []),
            },
            "signature": sig_result if sig_result is not None else {"verified": None},
            "risk_level": ("HIGH" if total_score >= 7 else ("MEDIUM" if total_score >= 4 else "LOW")),
            "generated_at": timestamp,
        }
        with open(report_json_path, "w", encoding="utf-8") as jf:
            json.dump(json_payload, jf, ensure_ascii=False, indent=2)
        saved_paths.append(report_json_path)

    for p in saved_paths:
        print(f"📝 Report saved to: {p}")

    # Return first path for convenience
    return saved_paths[0] if saved_paths else None
