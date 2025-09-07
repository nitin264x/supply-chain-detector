import sys
from typing import Optional

from analyzers.downloader import download_and_extract_npm
from analyzers.github_downloader import download_and_extract_github
from analyzers.metadata_checker import run_metadata_check
from analyzers.signature_checker import verify_with_cosign
from analyzers.static_analyzer import run_static_analysis
from analyzers.write_report import write_report
from analyzers.secrets_scanner import run_secrets_scan
from analyzers.sbom import generate_sbom
from analyzers.lockfile_checker import run_lockfile_and_scripts_check
from analyzers.typo_checker import run_typo_and_maintainer_check


def parse_args(argv):
    target: Optional[str] = None
    download = False
    report_format = "md"  # md | json | both
    fail_on: Optional[int] = None

    i = 1
    while i < len(argv):
        arg = argv[i]
        if target is None and not arg.startswith("--"):
            target = arg
            i += 1
            continue
        if arg == "--download":
            download = True
            i += 1
            continue
        if arg.startswith("--format="):
            report_format = arg.split("=", 1)[1]
            i += 1
            continue
        if arg.startswith("--fail-on="):
            try:
                fail_on = int(arg.split("=", 1)[1])
            except:
                print("❌ --fail-on must be an integer score (e.g., --fail-on=4)")
                sys.exit(2)
            i += 1
            continue
        # skip unknown flags gracefully
        i += 1

    return target, download, report_format, fail_on


def main(package_path, report_format: str = "md", fail_on: Optional[int] = None):
    print("🤖 Scanning:", package_path)

    static_result = run_static_analysis(package_path)
    metadata_result = run_metadata_check(package_path)
    secrets_result = run_secrets_scan(package_path)
    sbom_result = generate_sbom(package_path)
    lockfile_result = run_lockfile_and_scripts_check(package_path)
    typo_result = run_typo_and_maintainer_check(package_path)
    sig_result = None
    if str(package_path).startswith("github:") or str(package_path).startswith("docker:"):
        sig_result = verify_with_cosign(package_path)

    print("\n== Report ==")
    print(f"📊 Static Score: {static_result['score']}")
    print(f"📋 Metadata Score: {metadata_result['score']}")
    print(f"⚠️  Issues: {metadata_result['issues']}")

    total = (
        static_result["score"]
        + metadata_result["score"]
        + secrets_result["score"]
        + sbom_result["score"]
        + lockfile_result["score"]
        + typo_result["score"]
    )
    print(f"🧮 Final Risk Score: {total}")
    if total >= 5:
        print("🚨 RISK: HIGH")
    elif total >= 3:
        print("⚠️ RISK: MODERATE")
    else:
        print("✅ RISK: LOW")

    write_report(
        static_result,
        metadata_result,
        total,
        package_path,
        sig_result=sig_result,
        secrets_result=secrets_result,
        sbom_result=sbom_result,
        lockfile_result=lockfile_result,
        typo_result=typo_result,
        format=report_format,
    )

    if fail_on is not None and total >= fail_on:
        print(f"❌ Exiting with failure because total score {total} >= fail-on {fail_on}")
        sys.exit(1)


if __name__ == "__main__":
    print("📦 Starting robot...")
    print("Args:", sys.argv)

    target, download, report_format, fail_on = parse_args(sys.argv)

    if not target:
        print("❌ No package path or source given.")
        print("Usage examples:")
        print("  python main.py express --download --format=both --fail-on=4")
        print("  python main.py github:vercel/next.js --download --format=json")
        print("  python main.py ./my-local-package --format=md")
        sys.exit(2)

    if download:
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
    main(package_path, report_format=report_format, fail_on=fail_on)
