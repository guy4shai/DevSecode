const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");

let alertsProvider;
let currentFindings = [];
let alertPanel;

function activate(context) {
  alertsProvider = new AlertsProvider(context);
  vscode.window.registerTreeDataProvider("devsecodeAlerts", alertsProvider);

  watchGitleaksReport(context);

  let disposable = vscode.commands.registerCommand(
    "DevSecode.runScan",
    async (uri) => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders) {
        vscode.window.showErrorMessage(
          "No workspace folder found. Please open a folder first."
        );
        return;
      }

      let rootPath = uri?.fsPath
        ? path.dirname(uri.fsPath)
        : workspaceFolders[0].uri.fsPath;

      const configPathProject = path.join(rootPath, "gitleaks.toml");
      const extensionDir = context.extensionPath;
      const configPathFallback = path.join(extensionDir, "gitleaks.toml");
      const configToUse = fs.existsSync(configPathProject)
        ? configPathProject
        : fs.existsSync(configPathFallback)
        ? configPathFallback
        : null;

      const reportPath = path.join(rootPath, "gitleaks_report.json");
      const command = configToUse
        ? `gitleaks detect --config="${configToUse}" --no-git --source="${rootPath}" --redact --report-format=json --report-path="${reportPath}"`
        : `gitleaks detect --no-git --source="${rootPath}" --redact --report-format=json --report-path="${reportPath}"`;

      cp.exec("gitleaks version", (versionErr) => {
        if (versionErr) {
          vscode.window.showErrorMessage(
            "Gitleaks is not installed or not available in PATH. Install it from https://github.com/gitleaks/gitleaks/releases"
          );
          return;
        }
        const trivyConfigPathProject = path.join(rootPath, "trivy.yaml");
        const trivyConfigPathFallback = path.join(extensionDir, "trivy.yaml");
        const trivyConfigToUse = fs.existsSync(trivyConfigPathProject)
          ? trivyConfigPathProject
          : fs.existsSync(trivyConfigPathFallback)
          ? trivyConfigPathFallback
          : null;

        const trivyReportPath = path.join(rootPath, "trivy_report.json");
        const trivyCommand = trivyConfigToUse
          ? `trivy fs "${rootPath}" --config "${trivyConfigToUse}" --format json --output "${trivyReportPath}"`
          : `trivy fs "${rootPath}" --format json --output "${trivyReportPath}"`;

        vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "Running Security Scans...",
            cancellable: false,
          },
          () => {
            return new Promise((resolve) => {
              cp.exec(
                command,
                { maxBuffer: 1024 * 1000 },
                (err, stdout, stderr) => {
                  if (!fs.existsSync(reportPath)) {
                    vscode.window.showInformationMessage(
                      "No JSON report created. Possibly no leaks or an error occurred."
                    );
                    return resolve();
                  }

                  const rawContent = fs.readFileSync(reportPath, "utf8").trim();
                  if (!rawContent) {
                    vscode.window.showInformationMessage(
                      "No secrets found. The report file is empty."
                    );
                    return resolve();
                  }

                  let findings;
                  try {
                    findings = JSON.parse(rawContent);
                    currentFindings = findings;
                  } catch (parseErr) {
                    vscode.window.showWarningMessage(
                      "Scan completed, but JSON parse failed."
                    );
                    return resolve();
                  }

                  if (!Array.isArray(findings) || findings.length === 0) {
                    vscode.window.showInformationMessage(
                      "No secrets found in scan."
                    );
                  } else {
                    showDiagnostics(findings);
                  }

                  vscode.window.showInformationMessage(
                    "Secret Scan complete. Opening dashboard..."
                  );
                  showDashboard(context, findings);
                  alertsProvider.refresh();

                  cp.exec(
                    trivyCommand,
                    { maxBuffer: 1024 * 1000 },
                    (trivyErr) => {
                      if (trivyErr) {
                        vscode.window.showErrorMessage(
                          "Trivy scan failed. Ensure Trivy is installed and configured properly."
                        );
                        return;
                      }

                      if (!fs.existsSync(trivyReportPath)) {
                        vscode.window.showInformationMessage(
                          "No Trivy report created. Possibly no vulnerabilities or an error occurred."
                        );
                        return;
                      }

                      vscode.window.showInformationMessage(
                        "Trivy SCA scan completed successfully."
                      );
                    }
                  );
                }
              );
            });
          }
        );
      });
    }
  );

 const pythonCommand = `python3 "${path.join(extensionDir, 'DAST', 'dast.py')}"`;

cp.exec(pythonCommand, { maxBuffer: 1024 * 1000 }, (pyErr, pyStdout, pyStderr) => {
  if (pyErr) {
    vscode.window.showErrorMessage("DAST scan failed.");
    console.error(pyErr);
    return;
  }

  vscode.window.showInformationMessage("DAST scan completed successfully.");
});

  let showAlertsCommand = vscode.commands.registerCommand(
    "DevSecode.showAlerts",
    () => {
      showAlerts(context);
    }
  );

  let showAlertsCommand = vscode.commands.registerCommand(
    "DevSecode.showAlerts",
    () => {
      showAlerts(context);
    }
  );

  context.subscriptions.push(showAlertsCommand);
  context.subscriptions.push(disposable);

  let openAlertBannerCommand = vscode.commands.registerCommand(
    "DevSecode.openAlertBanner",
    (item) => {
      openAlertBanner(item);
    }
  );

  context.subscriptions.push(openAlertBannerCommand);
}

function watchGitleaksReport(context) {
  const reportPath = path.join(
    context.extensionPath,
    "UI",
    "gitleaks_report.json"
  );

  if (!fs.existsSync(reportPath)) {
    console.warn("gitleaks_report.json not found, skipping watch setup.");
    return;
  }

  const watcher = fs.watch(reportPath, (eventType) => {
    if (eventType === "change") {
      console.log("gitleaks_report.json changed, refreshing alerts...");
      alertsProvider.refresh();
    }
  });

  context.subscriptions.push({ dispose: () => watcher.close() });
}

function showDiagnostics(findings) {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("secretScanner");
  const diagnosticsMap = new Map();

  findings.forEach((finding) => {
    const fileUri = vscode.Uri.file(finding.File);
    const line = finding.StartLine ? finding.StartLine - 1 : 0;
    const range = new vscode.Range(
      new vscode.Position(line, 0),
      new vscode.Position(line, 80)
    );

    const tooltip = [
      `Rule: ${finding.RuleID}`,
      `Description: ${finding.Description || "Potential secret detected."}`,
      finding.Secret ? `Secret: ${finding.Secret}` : "",
      finding.redacted ? "(Secret redacted)" : "",
    ].join("\n");

    const message = `${finding.RuleID}: ${
      finding.Description || "Potential secret detected."
    }`;
    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      vscode.DiagnosticSeverity.Warning
    );
    diagnostic.source = "Secret Scanner";
    diagnostic.code = finding.RuleID;
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(fileUri, tooltip),
    ];

    if (!diagnosticsMap.has(fileUri)) {
      diagnosticsMap.set(fileUri, []);
    }
    diagnosticsMap.get(fileUri).push(diagnostic);
  });

  diagnosticCollection.clear();
  diagnosticsMap.forEach((diags, uri) => {
    diagnosticCollection.set(uri, diags);
  });
}

function showDashboard(context, findings) {
  const panel = vscode.window.createWebviewPanel(
    "devsecDashboard",
    "DevSecode Dashboard",
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  const htmlPath = path.join(context.extensionPath, "UI", "dashboard.html");
  let html = fs.readFileSync(htmlPath, "utf8");

  const imagePath = vscode.Uri.file(
    path.join(context.extensionPath, "devsecode_logo.png")
  );
  const imageUri = panel.webview.asWebviewUri(imagePath);

  // 🆕 קריאת הדוח של Trivy
  const trivyReportPath = path.join(
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || "",
    "trivy_report.json"
  );

  let trivyData = null;
  if (fs.existsSync(trivyReportPath)) {
    try {
      const trivyRaw = fs.readFileSync(trivyReportPath, "utf8");
      trivyData = JSON.parse(trivyRaw);
    } catch (err) {
      console.warn("Failed to parse trivy report");
    }
  }

  // 🧠 הוספת שני הדוחות כסקריפטים לדף
  html = html
    .replace('src="./devsecode_logo.png"', `src="${imageUri}"`)
    .replace(
      "</head>",
      `<script>
        const reportData = ${JSON.stringify(findings)};
        const scaData = ${JSON.stringify(trivyData || [])};
      </script></head>`
    );

  panel.webview.html = html;
}

function showAlerts(context) {
  const panel = vscode.window.createWebviewPanel(
    "devsecAlerts",
    "DevSecode Alerts",
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  const htmlPath = path.join(context.extensionPath, "UI", "alerts.html");
  let html = fs.readFileSync(htmlPath, "utf8");

  const jsonPath = vscode.Uri.file(
    path.join(context.extensionPath, "UI", "gitleaks_report.json")
  );
  const jsonWebUri = panel.webview.asWebviewUri(jsonPath);
  html = html.replace(
    "fetch('gitleaks_report.json')",
    `fetch('${jsonWebUri}')`
  );

  panel.webview.html = html;
}

function openAlertBanner(alertItem) {
  const panelTitle = `Alert: ${alertItem.RuleID}`;

  const alertPanel = vscode.window.createWebviewPanel(
    "alertDetail",
    panelTitle,
    vscode.ViewColumn.Active,
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.file(path.join(__dirname, "UI"))],
    }
  );

  const htmlPath = path.join(__dirname, "UI", "alertpage.html");
  let html = fs.readFileSync(htmlPath, "utf8");

  const reportData = currentFindings;

  const jsonUri = alertPanel.webview.asWebviewUri(
    vscode.Uri.file(path.join(__dirname, "UI", "gitleaks_report.json"))
  );

  html = html.replace(
    "</head>",
    `<script>
      const reportData = ${JSON.stringify(reportData)};
      const reportJsonUrl = "${jsonUri}";
      const targetRuleID = "${alertItem.RuleID}";
      const targetStartLine = ${alertItem.StartLine};
    </script></head>`
  );

  alertPanel.webview.html = html;

  alertPanel.webview.onDidReceiveMessage(
    (message) => {
      if (message.command === "goToLine") {
        const { filePath, lineNumber } = message;
        const uri = vscode.Uri.file(filePath);
        vscode.workspace.openTextDocument(uri).then((doc) => {
          vscode.window.showTextDocument(doc, {
            selection: new vscode.Range(
              new vscode.Position(lineNumber - 1, 0),
              new vscode.Position(lineNumber - 1, 0)
            ),
          });
        });
      }
    },
    undefined,
    []
  );
}

function deactivate() {}

class AlertsProvider {
  constructor(context) {
    this.context = context;
    this.reportPath = path.join(
      context.extensionPath,
      "UI",
      "gitleaks_report.json"
    );
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
  }

  refresh() {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren() {
    if (!currentFindings || currentFindings.length === 0) {
      return Promise.resolve([]);
    }

    const severityRank = {
      Critical: 0,
      High: 1,
      Medium: 2,
      Low: 3,
    };

    function getSeverity(entropy) {
      if (entropy > 4.5) return "Critical";
      if (entropy > 4) return "High";
      if (entropy > 3.5) return "Medium";
      return "Low";
    }

    const sortedFindings = currentFindings
      .map((item) => ({
        ...item,
        severity: getSeverity(item.Entropy),
      }))
      .sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

    return Promise.resolve(
      sortedFindings.map((item) => {
        const label = `${item.RuleID}: Line ${item.StartLine}`;
        const desc = item.Description || "No description";
        const severity = item.severity;

        const alertItem = new vscode.TreeItem(
          label,
          vscode.TreeItemCollapsibleState.None
        );

        alertItem.tooltip = `${desc}\nSeverity: ${severity}`;
        alertItem.description = severity;

        const iconFilename = `${severity.toLowerCase()}_icon.png`;
        alertItem.iconPath = vscode.Uri.file(
          path.join(this.context.extensionPath, iconFilename)
        );

        alertItem.command = {
          command: "DevSecode.openAlertBanner",
          title: "Open Alert",
          arguments: [item],
        };

        return alertItem;
      })
    );
  }
}

module.exports = {
  activate,
  deactivate,
};
