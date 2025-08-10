import datetime
import os


def write_report(static_result, metadata_result, total_score, output_path):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        "# 🔍 Security Scan Report",
        f"**Date:** {now}",
        "",
        "## 📊 Summary",
        f"- Static Score: `{static_result['score']}`",
        f"- Metadata Score: `{metadata_result['score']}`",
        f"- Final Risk Score: `{total_score}`",
        "",
        "## ⚠️ Detected Issues",
        "**Static Analysis:**",
        f"- {', '.join(static_result['issues']) if static_result['issues'] else 'None'}",
        "",
        "**Metadata Analysis:**",
        f"- {', '.join(metadata_result['issues']) if metadata_result['issues'] else 'None'}",
        "",
        "## 🧠 Risk Evaluation",
    ]

    if total_score >= 5:
        report_lines.append("🚨 **HIGH RISK**: Proceed with extreme caution!")
    elif total_score >= 3:
        report_lines.append("⚠️ **MODERATE RISK**: Review carefully before use.")
    else:
        report_lines.append("✅ **LOW RISK**: No major threats detected.")

    # 🔒 Create safe filename using package name and timestamp
    safe_name = output_path.replace("/", "_").replace("\\", "_").replace(":", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{safe_name}_{timestamp}.md"

    # 📂 Save report to permanent reports/ directory
    report_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(report_dir, report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print("📝 Report saved to:", report_path)
