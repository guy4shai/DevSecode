# DevSecode

> VS Code extension for automated secret scanning, vulnerability detection, and security reporting.

**Final Project – B.Sc. in Computer Science – College of Management**

DevSecode is a VS Code extension that scans your codebase for secrets, vulnerabilities, and insecure code patterns using tools like **Gitleaks**, **Trivy**, and **Bandit**. It helps you catch security issues early, directly from your editor.

---

## ✨ Features

- **Secret scanning (Gitleaks)** – Detect hardcoded tokens, passwords, and API keys.
- **Vulnerability scanning (Trivy)** – Find open-source and system-level vulnerabilities.
- **SAST – Static Application Security Testing (Bandit)** – Identify insecure Python code patterns.
- **Interactive alerts panel** – View, filter, and expand issues by severity in a dedicated sidebar.
- **Clickable vulnerability charts** – Explore issues visually by clicking chart segments in the dashboard.
- **One-click scans** – Run scans from the Command Palette or the right-click context menu.
- **Auto-fix suggestions** – Apply suggested fixes for supported findings.
- **PDF report generation** – Export findings into a styled PDF report with charts and summaries.
- **Tool auto-detection** – Get notified if required CLI tools are missing and offers installation instructions.

> Protect your repositories and avoid leaking sensitive data – directly from VS Code.

---

## 📦 Installation

DevSecode is installed directly from the Visual Studio Code Marketplace:

1. Open **Visual Studio Code**.
2. Go to the **Extensions** view (`Ctrl+Shift+X` on Windows/Linux, `Cmd+Shift+X` on macOS).
3. In the search bar, type **"DevSecode"**.
4. Select the **DevSecode** extension from the results and click **Install**.
5. Reload VS Code if prompted.
6. Follow the on-screen instructions provided by the extension – it will guide you through any additional setup steps and tool configuration required for running the scans.

---

## 🚀 Usage

1. **Open your project folder** in VS Code.
2. Open the **Command Palette**:
   - On Windows/Linux: `Ctrl+Shift+P`  
   - On macOS: `Cmd+Shift+P`
3. Search for **“DevSecode”** and choose the desired scan, for example:
   - `DevSecode: Run Secret Scan`
   - `DevSecode: Run Vulnerability Scan`
   - `DevSecode: Run SAST Scan`
4. View results in:
   - **Dashboard Panel** – Visual summaries, charts by severity and scan type.
   - **Alerts View** – Filterable, expandable list of issues by severity, file, and rule.
   - **Terminal Output** – Optional raw logs from the underlying tools.
5. Optionally:
   - Apply **auto-fix suggestions** where supported.
   - Generate a **PDF report** from the command or UI to share with your team.

---

