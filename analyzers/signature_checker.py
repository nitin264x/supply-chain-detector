import os
import subprocess


def verify_with_cosign(target):
    cosign_path = os.path.join(os.getcwd(), "tools", "cosign.exe")
    try:
        result = subprocess.run(
            [cosign_path, "verify", target],
            capture_output=True,
            text=True
        )
        if "Verified OK" in result.stdout:
            return {"verified": True, "details": result.stdout}
        else:
            return {"verified": False, "details": result.stdout + result.stderr}
    except Exception as e:
        return {"verified": False, "error": str(e)}
    
if __name__ == "__main__":
    target = "ghcr.io/sigstore/sample-container"  # Example signed container
    result = verify_with_cosign(target)
    print(result)
