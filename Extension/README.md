# DevSecode
**Final Project – B.Sc – College Of Management**  

DevSecode is a powerful VS Code extension that scans your codebase for **secrets**, **vulnerabilities**, and **security issues** using tools like [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://github.com/aquasecurity/trivy) and [Bandit](https://github.com/PyCQA/bandit).

## Features
- **Scan for secrets using Gitleaks** – Find hardcoded tokens, passwords, and API keys  
- **Vulnerability scanning using Trivy** – Detect open-source and system vulnerabilities  
- **SAST - Static Application Security Testing** – Identify insecure code patterns using Bandit 
- **Interactive alerts panel** – View and filter issues by severity in a sidebar view  
- **Clickable vulnerability chart** – Explore issues by clicking on chart segments in the dashboard  
- **One-click scan** – Run scans from the Command Palette or context menu  
- **Auto-fix suggestions** – Apply suggested fixes for supported issues  
- **PDF report generation** – Export findings into a styled report with charts  
- **Tool auto-detection** – Alerts you if required tools are missing and offers installation instructions

## Installation
Ensure the following tools are installed based on the scans you want to perform:

### macOS:
```bash
brew install gitleaks trivy bandit 
```

### Windows:
```bash
scoop install gitleaks trivy bandit semgrep    # Windows (Scoop)  
choco install gitleaks trivy bandit semgrep    # Windows (Chocolatey)  
```

### Windows - Manual Installation:

- [Gitleaks](https://github.com/gitleaks/gitleaks/releases) – Secret scanning  
- [Trivy](https://github.com/aquasecurity/trivy/releases) – Vulnerability scanning  
- [Bandit](https://bandit.readthedocs.io/) – Python static analysis  

1. Download the binaries or installers from the official tool websites (linked above)  
2. Extract or install the tools  
3. Add the executable paths (e.g., `C:\Tools\trivy`, `C:\Python311\Scripts`) to your **System Environment Variables → PATH**  
4. Restart VS Code after making changes to `PATH`


## Usage
1. Open your project folder in VS Code  
2. Press `Ctrl+Shift+P` → Select a scan → **Run Secret Scan**
3. View results in:
   - **Dashboard Panel** – Visual summaries and charts  
   - **Alerts View** – Expandable, filterable issue list by severity  
   - **Terminal Output** – Raw scan logs (optional)

---
Protect your repositories and avoid leaking sensitive data!
# DevSecode
