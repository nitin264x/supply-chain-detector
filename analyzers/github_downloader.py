import io
import os
import tempfile
import zipfile

import requests


def download_and_extract_github(repo_path):
    print(f"🌐 Downloading GitHub repo: {repo_path}")
    owner, repo = repo_path.split("/")
    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"

    response = requests.get(zip_url)
    response.raise_for_status()

    temp_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        z.extractall(temp_dir)

    # Extracted folder will be something like next.js-main/
    subfolders = os.listdir(temp_dir)
    if not subfolders:
        raise Exception("❌ No content found in GitHub ZIP")
    extracted_path = os.path.join(temp_dir, subfolders[0])
    
    print(f"✅ Repo extracted to: {extracted_path}")
    return extracted_path
