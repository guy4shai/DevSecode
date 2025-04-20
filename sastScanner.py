import os
import subprocess

def run_command(command, tool_name):
    print(f"\n🔍 Running {tool_name}...")
    try:
        result = subprocess.run(command, shell=True, check=True)
        print(f"✅ {tool_name} completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ {tool_name} may have completed with warnings.")
        print(f"↳ {tool_name} exited with code {e.returncode}")

def run_sast_scans(root_path):
    config_dir = os.path.join(root_path, 'scanner-config')
    report_dir = os.path.join(root_path, 'SecrectDIR')
    os.makedirs(report_dir, exist_ok=True)

    tools = [
        {
            'name': 'bandit',
            'config_file': None,
            'output': os.path.join(report_dir, 'bandit.json'),
            'command': lambda _: f'bandit -r "{root_path}" -f json -o "{os.path.join(report_dir, "bandit.json")}"'
        },
        {
            'name': 'semgrep',
            'config_file': os.path.join(config_dir, 'semgrep.yaml'),
            'output': os.path.join(report_dir, 'semgrep.json'),
            'command': lambda config: (
                f'semgrep scan --config "{config}" --json -o "{os.path.join(report_dir, "semgrep.json")}" "{root_path}"'
                if config and os.path.exists(config)
                else f'semgrep scan --config auto --json -o "{os.path.join(report_dir, "semgrep.json")}" "{root_path}"'
            )
        },
        {
            'name': 'trivy',
            'config_file': None,
            'output': os.path.join(report_dir, 'trivy.json'),
            'command': lambda _: f'trivy fs --scanners vuln --format json --output "{os.path.join(report_dir, "trivy.json")}" "{root_path}"'
        }
    ]

    print(f"\n📁 Scanning path: {root_path}")
    print(f"📄 Report output directory: {report_dir}")

    for tool in tools:
        config = tool['config_file']
        command = tool['command'](config)
        run_command(command, tool['name'])

    print("\n✅ All scans complete. Check SecretDIR for reports.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        root_path = sys.argv[1]
        run_sast_scans(root_path)
    else:
        print("❗ Usage: python3 sastScanner.py <path-to-scan>")
