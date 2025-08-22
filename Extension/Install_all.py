import os
import platform
import subprocess
import sys
import urllib.request
import zipfile
import tarfile
from pathlib import Path

def run(cmd):
    print(f"[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] Failed: {cmd}")
        sys.exit(1)

def install_gitleaks():
    if platform.system() == "Windows":
        url = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.3/gitleaks_8.18.3_windows_x86_64.zip"
        zip_path = "gitleaks.zip"
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("gitleaks")
        os.rename("gitleaks/gitleaks.exe", "gitleaks.exe")
        os.remove(zip_path)
    else:
        run("curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.3/gitleaks_8.18.3_linux_x64.tar.gz -o gitleaks.tar.gz")
        with tarfile.open("gitleaks.tar.gz") as tar:
            tar.extractall()
        run("sudo mv gitleaks /usr/local/bin/")
        os.remove("gitleaks.tar.gz")

def install_bandit():
    run(f"{sys.executable} -m pip install bandit")

def install_trivy():
    if platform.system() == "Windows":
        url = "https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Windows-64bit.zip"
        zip_path = "trivy.zip"
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("trivy")
        os.rename("trivy/trivy.exe", "trivy.exe")
        os.remove(zip_path)
    else:
        run("sudo apt install wget -y")
        run("wget https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz -O trivy.tar.gz")
        with tarfile.open("trivy.tar.gz") as tar:
            tar.extractall()
        run("sudo mv trivy /usr/local/bin/")
        os.remove("trivy.tar.gz")

def install_zap():
    zap_dir = Path("zap")
    zap_dir.mkdir(exist_ok=True)
    if platform.system() == "Windows":
        zap_url = "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Windows.exe"
        exe_path = zap_dir / "ZAP_2.16.1_Windows.exe"
        urllib.request.urlretrieve(zap_url, exe_path)
        print(f"[i] ZAP installer saved at {exe_path}. Please run it manually.")
    elif platform.system() == "Darwin":
        zap_url = "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_macos.dmg"
        dmg_path = zap_dir / "ZAP_2.16.1_macos.dmg"
        urllib.request.urlretrieve(zap_url, dmg_path)
        print(f"[i] ZAP installer saved at {dmg_path}. Please install manually.")
    else:
        zap_url = "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz"
        tar_path = zap_dir / "ZAP_Linux.tar.gz"
        urllib.request.urlretrieve(zap_url, tar_path)
        with tarfile.open(tar_path) as tar:
            tar.extractall(zap_dir)
        print(f"[+] ZAP extracted to {zap_dir}")

if __name__ == "__main__":
    print("[*] Installing DevSec tools...")
    install_gitleaks()
    install_bandit()
    install_trivy()
    install_zap()
    print("[✓] All tools downloaded and installed (or prepared for manual install if needed).")
