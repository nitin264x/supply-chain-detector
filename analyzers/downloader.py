import os
import shutil
import tarfile
import tempfile

import requests


def download_and_extract_npm(package_name):
    print(f"🌐 Downloading npm package: {package_name}")
    registry_url = f"https://registry.npmjs.org/{package_name}"
    response = requests.get(registry_url)
    response.raise_for_status()

    data = response.json()
    latest_version = data["dist-tags"]["latest"]
    tarball_url = data["versions"][latest_version]["dist"]["tarball"]

    tarball_response = requests.get(tarball_url, stream=True)
    tarball_response.raise_for_status()

    temp_dir = tempfile.mkdtemp()
    tar_path = os.path.join(temp_dir, f"{package_name}.tgz")

    with open(tar_path, "wb") as f:
        f.write(tarball_response.content)

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=temp_dir)

    # npm packages often have "package/" as root folder
    package_folder = os.path.join(temp_dir, "package")

    print(f"📦 Package extracted to: {package_folder}")
    return package_folder

if __name__ == "__main__":
    download_and_extract_npm("express")

