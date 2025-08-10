import sys

from analyzers.downloader import download_and_extract_npm
from analyzers.github_downloader import download_and_extract_github
from analyzers.metadata_checker import run_metadata_check
from analyzers.static_analyzer import run_static_analysis
from analyzers.write_report import write_report


def main(package_path):
    print("🤖 Scanning:", package_path)

    static_result = run_static_analysis(package_path)
    metadata_result = run_metadata_check(package_path)

    print("\n== Report ==")
    print(f"📊 Static Score: {static_result['score']}")
    print(f"📋 Metadata Score: {metadata_result['score']}")
    print(f"⚠️  Issues: {metadata_result['issues']}")

    total = static_result["score"] + metadata_result["score"]
    print(f"🧮 Final Risk Score: {total}")
    if total >= 5:
        print("🚨 RISK: HIGH")
    elif total >= 3:
        print("⚠️ RISK: MODERATE")
    else:
        print("✅ RISK: LOW")

    write_report(static_result, metadata_result, total, package_path)


if __name__ == "__main__":
    print("📦 Starting robot...")
    print("Args:", sys.argv)

    if len(sys.argv) > 1:
        target = sys.argv[1]

        # --download used?
        if len(sys.argv) > 2 and sys.argv[2] == "--download":
            if ":" in target:
                source, name = target.split(":", 1)

                if source == "npm":
                    package_path = download_and_extract_npm(name)

                elif source == "github":
                    package_path = download_and_extract_github(name)

                else:
                    print(f"❌ Unknown source: {source}")
                    sys.exit(1)
            else:
                # Default to NPM if no source prefix
                package_path = download_and_extract_npm(target)
        else:
            # If not downloading, assume it's a local path
            package_path = target

        # Run scanner
        main(package_path)

    else:
        print("❌ No package path or source given.")
        print("Usage examples:")
        print("  python main.py express --download")
        print("  python main.py github:vercel/next.js --download")
        print("  python main.py ./my-local-package")
