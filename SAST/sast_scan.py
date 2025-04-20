import os
import json
import subprocess
from tabulate import tabulate

def run_sast_scan(target_dir):
    result = subprocess.run(
        ["semgrep", "--config", "p/default", "--json", target_dir],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def extract_findings(sast_results):
    findings = []
    for result in sast_results.get("results", []):
        findings.append({
            "rule_id": result.get("check_id"),
            "message": result.get("extra", {}).get("message"),
            "severity": result.get("extra", {}).get("severity"),
            "path": result.get("path"),
            "line": result.get("start", {}).get("line"),
        })
    return findings

def save_json(output_path, data):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n✅ SAST results saved to: {output_path}")

def print_table(findings):
    table = [[f["rule_id"], f["path"], f["line"], f["severity"]] for f in findings]
    print("\n=== SAST Report ===")
    print(tabulate(table, headers=["Rule ID", "File", "Line", "Severity"], tablefmt="grid"))

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.abspath(os.path.join(script_dir, ".."))  # סריקה של כל הפרויקט
    output_path = os.path.abspath(os.path.join(script_dir, "..", "SecrectDIR", "sast_output.json"))

    sast_data = run_sast_scan(target_dir)
    findings = extract_findings(sast_data)

    save_json(output_path, {"sast": findings})
    print_table(findings)

if __name__ == "__main__":
    main()
