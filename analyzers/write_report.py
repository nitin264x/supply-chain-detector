import os
from datetime import datetime


def write_report(static_result, metadata_result, total_score, package_path, sig_result=None):
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
    report_filename = f"{safe_package_name}_{timestamp}.md"
    report_path = os.path.join(report_dir, report_filename)

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

    # Save report
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    
    print(f"📝 Report saved to: {report_path}")
