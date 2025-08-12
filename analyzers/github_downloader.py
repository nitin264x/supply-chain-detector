import io
import os
import tempfile
import zipfile

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _create_retrying_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    # Identify client to GitHub and use token if provided
    session.headers.update({"User-Agent": "supply-chain-detector/1.0"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        session.headers.update({"Authorization": f"token {token}"})
    return session


def _get_default_branch(session: requests.Session, owner: str, repo: str) -> str:
    default_branch = "main"
    try:
        resp = session.get(f"https://api.github.com/repos/{owner}/{repo}", timeout=10)
        if resp.ok:
            api_branch = (resp.json() or {}).get("default_branch")
            if api_branch:
                default_branch = api_branch
    except requests.RequestException:
        # Fall back to defaults if API unavailable
        pass
    return default_branch


def _download_zip_to_memory(session: requests.Session, zip_url: str) -> io.BytesIO:
    with session.get(zip_url, stream=True, timeout=(10, 180)) as response:
        response.raise_for_status()
        buffer = io.BytesIO()
        for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
            if chunk:
                buffer.write(chunk)
        buffer.seek(0)
        return buffer


def download_and_extract_github(repo_path):
    print(f"🌐 Downloading GitHub repo: {repo_path}")
    owner, repo = repo_path.split("/")

    session = _create_retrying_session()

    # Determine branch to download
    branch = _get_default_branch(session, owner, repo)

    # Use codeload, which is optimized for archive downloads
    base_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/"

    temp_dir = tempfile.mkdtemp()

    # Try default branch, then fall back to common alternatives
    candidate_branches = [branch, "main", "master", "canary"]
    last_error = None

    for candidate in candidate_branches:
        zip_url = base_url + candidate
        try:
            zip_bytes = _download_zip_to_memory(session, zip_url)
            with zipfile.ZipFile(zip_bytes) as zf:
                zf.extractall(temp_dir)
            # Success
            subfolders = os.listdir(temp_dir)
            if not subfolders:
                raise Exception("❌ No content found in GitHub ZIP")
            extracted_path = os.path.join(temp_dir, subfolders[0])
            print(f"✅ Repo extracted to: {extracted_path}")
            return extracted_path
        except (requests.RequestException, zipfile.BadZipFile, zipfile.LargeZipFile) as e:
            last_error = e
            # Try next candidate branch
            continue

    # If all candidates failed, raise the last error with context
    msg = (
        f"❌ Failed to download GitHub repo '{owner}/{repo}'. "
        f"Tried branches: {candidate_branches}. Last error: {last_error}"
    )
    raise Exception(msg)
