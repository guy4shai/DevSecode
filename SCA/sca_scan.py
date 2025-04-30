# import os
# import json
# import subprocess
# import shutil
# from tabulate import tabulate

# SCA_OUTPUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "SecrectDIR"))

# def run_command(command, label):
#     print(f"\n🔍 Running {label}...\n$ {' '.join(command)}")
#     result = subprocess.run(command, capture_output=True, text=True)
#     try:
#         return json.loads(result.stdout)
#     except json.JSONDecodeError:
#         print(f"❌ Failed to parse JSON from {label}:\n{result.stderr}")
#         return {}

# # ========== Trivy ==========
# def run_trivy():
#     return run_command(["trivy", "fs", "--scanners", "vuln", "--format", "json", "."], "Trivy")

# def extract_trivy(data):
#     vulns = []
#     for result in data.get("Results", []):
#         for vuln in result.get("Vulnerabilities", []):
#             vulns.append({
#                 "tool": "Trivy",
#                 "cve_id": vuln.get("VulnerabilityID"),
#                 "package": vuln.get("PkgName"),
#                 "version": vuln.get("InstalledVersion"),
#                 "severity": vuln.get("Severity"),
#             })
#     return vulns

# # ========== Syft + Grype ==========
# def run_syft():
#     subprocess.run(["syft", ".", "-o", "json", "--output", "sbom.json", "--quiet"])

# def run_grype():
#     return run_command(["grype", "sbom:sbom.json", "-o", "json"], "Grype")

# def extract_grype(data):
#     vulns = []
#     for match in data.get("matches", []):
#         vuln = match.get("vulnerability", {})
#         artifact = match.get("artifact", {})
#         vulns.append({
#             "tool": "Grype",
#             "cve_id": vuln.get("id"),
#             "package": artifact.get("name"),
#             "version": artifact.get("version"),
#             "severity": vuln.get("severity"),
#         })
#     return vulns

# # ========== עזר ==========
# def save_json(name, data):
#     os.makedirs(SCA_OUTPUT, exist_ok=True)
#     path = os.path.join(SCA_OUTPUT, name)
#     with open(path, "w") as f:
#         json.dump(data, f, indent=4)
#     print(f"✅ Saved to {path}")

# def print_table(vulns, title):
#     if not vulns:
#         print(f"\n🚫 No results found in {title}")
#         return
#     print(f"\n=== {title} ===")
#     table = [[v["tool"], v["cve_id"], v["package"], v["version"], v["severity"]] for v in vulns]
#     print(tabulate(table, headers=["Tool", "CVE", "Package", "Version", "Severity"], tablefmt="grid"))

# def main():
#     all_vulns = []

#     # Trivy
#     if shutil.which("trivy"):
#         trivy_raw = run_trivy()
#         trivy_vulns = extract_trivy(trivy_raw)
#         save_json("sca_trivy_output.json", trivy_vulns)
#         print_table(trivy_vulns, "Trivy SCA")
#         all_vulns.extend(trivy_vulns)
#     else:
#         print("⚠️  Trivy not found. Skipping...")

#     # Grype + Syft
#     if shutil.which("syft") and shutil.which("grype"):
#         run_syft()
#         grype_raw = run_grype()
#         grype_vulns = extract_grype(grype_raw)
#         save_json("sca_grype_output.json", grype_vulns)
#         print_table(grype_vulns, "Grype SCA")
#         all_vulns.extend(grype_vulns)
#     else:
#         print("⚠️  Syft or Grype not found. Skipping Grype SCA...")

#     # איחוד כל הפלטים
#     save_json("sca_all_combined.json", all_vulns)

# if __name__ == "__main__":
#     main()


# תחילת הקובץ
import os
import json
import subprocess
import shutil
from tabulate import tabulate

# ==============================
# שנה את SCA_OUTPUT כך:
# אם הסקריפט שלך נמצא בתיקייה conainterScanning או SCA, 
# תמיד נעלה תיקייה אחת למעלה ואז ניכנס ל-UI/json_output
SCRIPT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SCA_OUTPUT = os.path.join(PROJECT_ROOT, "UI", "json_output")
# ==============================

def run_command(command, label):
    print(f"\n🔍 Running {label}...\n$ {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"❌ Failed to parse JSON from {label}:\n{result.stderr}")
        return {}

# ========== Trivy ==========
def run_trivy():
    return run_command(["trivy", "fs", "--scanners", "vuln", "--format", "json", "."], "Trivy")

def extract_trivy(data):
    vulns = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulns.append({
                "tool": "Trivy",
                "cve_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "version": vuln.get("InstalledVersion"),
                "severity": vuln.get("Severity"),
            })
    return vulns

# ========== Syft + Grype ==========
def run_syft():
    subprocess.run(["syft", ".", "-o", "json", "--output", "sbom.json", "--quiet"])

def run_grype():
    return run_command(["grype", "sbom:sbom.json", "-o", "json"], "Grype")

def extract_grype(data):
    vulns = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vulns.append({
            "tool": "Grype",
            "cve_id": vuln.get("id"),
            "package": artifact.get("name"),
            "version": artifact.get("version"),
            "severity": vuln.get("severity"),
        })
    return vulns

# ========== עזר ==========
def save_json(name, data):
    os.makedirs(SCA_OUTPUT, exist_ok=True)
    path = os.path.join(SCA_OUTPUT, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"✅ Saved to {path}")

def print_table(vulns, title):
    if not vulns:
        print(f"\n🚫 No results found in {title}")
        return
    print(f"\n=== {title} ===")
    table = [[v["tool"], v["cve_id"], v["package"], v["version"], v["severity"]] for v in vulns]
    print(tabulate(table, headers=["Tool", "CVE", "Package", "Version", "Severity"], tablefmt="grid"))

def main():
    all_vulns = []

    # Trivy
    if shutil.which("trivy"):
        trivy_raw = run_trivy()
        trivy_vulns = extract_trivy(trivy_raw)
        save_json("sca_trivy_output.json", trivy_vulns)
        print_table(trivy_vulns, "Trivy SCA")
        all_vulns.extend(trivy_vulns)
    else:
        print("⚠️  Trivy not found. Skipping...")

    # Grype + Syft
    if shutil.which("syft") and shutil.which("grype"):
        run_syft()
        grype_raw = run_grype()
        grype_vulns = extract_grype(grype_raw)
        save_json("sca_grype_output.json", grype_vulns)
        print_table(grype_vulns, "Grype SCA")
        all_vulns.extend(grype_vulns)
    else:
        print("⚠️  Syft or Grype not found. Skipping Grype SCA...")

    # איחוד כל הפלטים
    save_json("sca_all_combined.json", all_vulns)

if __name__ == "__main__":
    main()
