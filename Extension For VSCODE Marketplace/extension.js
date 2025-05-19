const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const { generatePDFReport } = require('./add-pdf/reportGenerator');


let alertsProvider;
let currentFindings = [];
let alertPanel;
let currentTrivyFindings = [];
let currentBanditFindings = [];

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

                      let trivyData = [];
                      try {
                        const trivyRaw = fs.readFileSync(trivyReportPath, 'utf8');
                        trivyData = JSON.parse(trivyRaw);
                        console.log("✅ Trivy report loaded successfully.");
                      } catch (err) {
                        vscode.window.showWarningMessage("⚠️ Failed to parse trivy_report.json.");
                        console.warn("Trivy parsing error:", err);
                      }

                      // 💡 אתה יכול להעביר את הנתונים לדאשבורד או להוסיף אותם ל-alertsProvider אם צריך

                      vscode.window.showInformationMessage(
                        "Trivy SCA scan completed successfully."
                      );
                      
                      try {
                        currentTrivyFindings = JSON.parse(fs.readFileSync(trivyReportPath, 'utf8'));
                      } catch (e) {
                        currentTrivyFindings = [];
                      }

                      const banditReportPath = path.join(rootPath, "bandit_report.json");
                      const banditCommand = `bandit -r "${rootPath}" --exclude "${rootPath}/node_modules,${rootPath}/venv" -f json -o "${banditReportPath}"`;


                      const semgrepReportPath = path.join(rootPath, "semgrep_report.json");
                      const semgrepCommand = `semgrep --config auto --json --output "${semgrepReportPath}" "${rootPath}"`;
                      
                      
                      const util = require('util');
                      const exec = util.promisify(cp.exec);
                      
                      (async () => {
                        try {
                          await exec(semgrepCommand, { maxBuffer: 1024 * 1000 });
                          vscode.window.showInformationMessage("✅ Semgrep scan completed.");
                        } catch (e) {
                          vscode.window.showWarningMessage("❌ Semgrep scan failed.");
                          console.error("Semgrep error:", e.stderr || e);
                        }
                      
                        
                        try {
                          await exec(banditCommand, { maxBuffer: 1024 * 1000 });
                          vscode.window.showInformationMessage("✅ Bandit scan completed.");
                        } catch (e) {
                          console.error("Bandit error:", e.stderr || e);
                        }
                        
                        let banditData = [];

                        try {
                          const banditRaw = fs.readFileSync(banditReportPath, 'utf8');
                          banditData = JSON.parse(banditRaw);
                          console.log("✅ Bandit report loaded successfully.");
                        } catch (err) {
                          vscode.window.showWarningMessage("⚠️ Failed to parse bandit_report.json.");
                          console.warn("Bandit parsing error:", err);
                        }

                        vscode.window.showInformationMessage("Bandit scan completed successfully.");

                        try {
                          currentBanditFindings = banditData.results || [];
                        } catch (e) {
                          currentBanditFindings = [];
                        }

                        showDashboard(context, findings);
                        alertsProvider.refresh(); 
                        resolve(); // ✅ מסיים את הספינר של VS Code
                      })();        
                                   
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

  
  context.subscriptions.push(disposable);

  let openAlertBannerCommand = vscode.commands.registerCommand(
    "DevSecode.openAlertBanner",
    (item) => {
      openAlertBanner(item);
    }
  );

  context.subscriptions.push(openAlertBannerCommand);
  const generatePdfCommand = vscode.commands.registerCommand('devsecode.generateCustomPDF', async () => {
    // 🟩 בחירת חומרות
    const severityOptions = await vscode.window.showQuickPick(['Critical','High', 'Medium', 'Low'], {
      canPickMany: true,
      placeHolder: 'Select severity levels to include'
    });

    if (!severityOptions || severityOptions.length === 0) {
      vscode.window.showErrorMessage('❌ Please select at least one severity level.');
      return;
    }

    // 🟩 בחירת מיון
    const sortOrder = await vscode.window.showQuickPick(['Severity', 'Line Number'], {
      placeHolder: 'Select how to sort the report'
    });

    if (!sortOrder) {
      vscode.window.showErrorMessage('❌ Please select a sort order for the report.');
      return;
    }

    const sortKey = sortOrder === 'Line Number' ? 'line' : 'severity';

    // 🟩 איתור תיקיית העבודה
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      vscode.window.showErrorMessage('❌ No workspace folder found.');
      return;
    }
    const workspacePath = workspaceFolders[0].uri.fsPath;

    // 🟩 קונפיגורציית הדוח
    const config = {
      selectedSeverities: severityOptions, // ✅ רמות חומרה שנבחרו
      sortBy: sortKey,
      workspacePath: workspacePath
    };

    // שמירה מקומית של config (לא חובה, רק לצורך פיתוח)
    const configPath = path.join(__dirname, 'add-pdf', 'report.config.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

    // 🟩 טוען את הדוח JSON
    const findingsPath = path.join(__dirname, 'UI', 'gitleaks_report.json');
    if (!fs.existsSync(findingsPath)) {
      vscode.window.showErrorMessage('❌ Could not find gitleaks_report.json in UI folder.');
      return;
    }
    const trivyPath = path.join(workspacePath, 'trivy_report.json');
    const semgrepPath = path.join(workspacePath, 'semgrep_report.json');
    const banditPath = path.join(workspacePath, 'bandit_report.json');

    let trivyFindings = [];
    let semgrepFindings = [];
    let banditFindings = [];

    if (fs.existsSync(trivyPath)) {
      try {
        trivyFindings = JSON.parse(fs.readFileSync(trivyPath, 'utf-8'));
      } catch (e) {
        vscode.window.showWarningMessage("⚠️ Failed to load trivy_report.json.");
      }
    }

    if (fs.existsSync(semgrepPath)) {
      try {
        semgrepFindings = JSON.parse(fs.readFileSync(semgrepPath, 'utf-8'));
      } catch (e) {
        vscode.window.showWarningMessage("⚠️ Failed to load semgrep_report.json.");
      }
    }

    if (fs.existsSync(banditPath)) {
      try {
        banditFindings = JSON.parse(fs.readFileSync(banditPath, 'utf-8'));
      } catch (e) {
        vscode.window.showWarningMessage("⚠️ Failed to load bandit_report.json.");
      }
    }
    let findings;
    try {
      const findingsRaw = fs.readFileSync(findingsPath, 'utf-8');
      findings = JSON.parse(findingsRaw);
    } catch (e) {
      vscode.window.showErrorMessage('❌ Failed to read or parse gitleaks_report.json.');
      return;
    }

    const reportPath = await generatePDFReport(findings, config, {
      trivyFindings,
      semgrepFindings,
      banditFindings
    });
    // ✅ פתיחת הדוח לאחר יצירתו
    vscode.window.showInformationMessage('✅ PDF report generated successfully.', 'Open Report')
      .then(async selection => {
        if (selection === 'Open Report') {
          try {
            const open = await import('open').then(mod => mod.default);
            await open(reportPath);
          } catch (err) {
            vscode.window.showErrorMessage(`❌ Failed to open the report: ${err.message}`);
          }
        }
      });
  });

  context.subscriptions.push(generatePdfCommand);

  // 🟩 כפתור בשורת הסטטוס
  const pdfStatusBarButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  pdfStatusBarButton.command = 'devsecode.generateCustomPDF';
  pdfStatusBarButton.text = '$(file-pdf) Generate PDF Report';
  pdfStatusBarButton.tooltip = 'Click to generate a custom PDF report';
  pdfStatusBarButton.show();

  context.subscriptions.push(pdfStatusBarButton);
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

      try {
        const rawContent = fs.readFileSync(reportPath, "utf8").trim();
        if (rawContent) {
          const findings = JSON.parse(rawContent);
          currentFindings = findings;
        } else {
          currentFindings = [];
        }
      } catch (err) {
        console.warn("Failed to parse updated gitleaks_report.json", err);
        currentFindings = [];
      }

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

    // 📘 קריאת דוח Bandit
  const banditReportPath = path.join(
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || "",
    "bandit_report.json"
  );

  let banditData = null;
  if (fs.existsSync(banditReportPath)) {
    try {
      const rawBandit = fs.readFileSync(banditReportPath, "utf8");
      banditData = JSON.parse(rawBandit);
    } catch (err) {
      vscode.window.showWarningMessage("⚠️ Failed to parse bandit_report.json.");
      console.warn("Bandit parsing error:", err);
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
        const banditData = ${JSON.stringify(banditData || [])};
      </script></head>`
    );

  panel.webview.html = html;
}


function openAlertBanner(alertItem) {
  const vscode = require('vscode');
  const path = require('path');
  const fs = require('fs');

  const id = alertItem.RuleID || alertItem.VulnerabilityID || alertItem.test_name || "Unknown";
  const panelTitle = `Alert: ${id}`;

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

  
  let reportData = [];

  if (alertItem.VulnerabilityID) {
      // Trivy
      if (typeof currentTrivyFindings !== "undefined" && currentTrivyFindings.Results) {
          reportData = currentTrivyFindings.Results.flatMap(result => result.Vulnerabilities || []);
      }
  } else if (alertItem.test_name || alertItem.issue_text || alertItem.issue_severity) {
      // Bandit
      if (typeof currentBanditFindings !== "undefined" && currentBanditFindings.results) {
          reportData = currentBanditFindings.results;
      }
  } else {
      // Gitleaks
      if (typeof currentFindings !== "undefined") {
          reportData = currentFindings;
      }
  }


  

  // שים לב, לשלב גם נתיב קובץ של האלרט אם קיים (ל-Gitleaks או Trivy)
  const filePath = alertItem.FilePath || (alertItem.Location && alertItem.Location.Path) || alertItem.filename || "";
  const startLine = alertItem.StartLine || alertItem.line_number || 0;
  
  html = html.replace(
    "</head>",
    `<script>
      const reportData = ${JSON.stringify(reportData)};
      const targetRuleID = "${id}";
      const targetStartLine = ${startLine || 0};
      const alertItem = ${JSON.stringify(alertItem)};
      const filePath = ${JSON.stringify(filePath)};
    </script></head>`
  );

  alertPanel.webview.html = html;

  alertPanel.webview.onDidReceiveMessage(
    message => {
      if (message.command === "goToLine") {
        const { filePath, lineNumber } = message;
        if (filePath && lineNumber) {
          const uri = vscode.Uri.file(filePath);
          vscode.workspace.openTextDocument(uri).then(doc => {
            vscode.window.showTextDocument(doc, {
              selection: new vscode.Range(
                new vscode.Position(lineNumber - 1, 0),
                new vscode.Position(lineNumber - 1,Number.MAX_SAFE_INTEGER)
              ),
            });
          });
        }
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

    // אפשר לשמור קבצי דיווח כאן אם צריך, או להוריד את זה אם לא בשימוש
    this.reportPath = path.join(context.extensionPath, "UI", "gitleaks_report.json");

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
   
    const combinedFindings = [
      ...(currentFindings || []),
      ...(currentTrivyFindings?.Results?.flatMap(r => r.Vulnerabilities || []) || []),
      ...(currentBanditFindings || [])
    ];

    if (combinedFindings.length === 0) {
      return Promise.resolve([]);
    }

    const severityRank = {
      Critical: 0,
      High: 1,
      Medium: 2,
      Low: 3,
      Unknown: 4
    };

    // פונקציה אחידה להערכת חומרה לפי מאפיינים שונים בממצאים השונים
    function getSeverity(item) {
      // Gitleaks משתמש ב-Entropy
      if (item.Entropy !== undefined) {
        if (item.Entropy > 4.5) return "Critical";
        if (item.Entropy > 4) return "High";
        if (item.Entropy > 3.5) return "Medium";
        return "Low";
      }

      // Trivy, Semgrep, Bandit משתמשים ב-Severity או Level
      if (item.Severity) {
        const sev = item.Severity.toLowerCase();
        if (sev === "critical") return "Critical";
        if (sev === "high") return "High";
        if (sev === "medium") return "Medium";
        if (sev === "low") return "Low";
      }
      if (item.Level) {
        const lvl = item.Level.toLowerCase();
        if (lvl === "critical") return "Critical";
        if (lvl === "high") return "High";
        if (lvl === "medium") return "Medium";
        if (lvl === "low") return "Low";
      }
      if (item.issue_severity) {
        const issue = item.issue_severity.toLowerCase();
        if (issue === "critical") return "Critical";
        if (issue === "high") return "High";
        if (issue === "medium") return "Medium";
        if (issue === "low") return "Low";
      }

      return "Unknown";
    }

    // פונקציה אחידה לאיתור מזהה (RuleID, VulnerabilityID, CheckID וכו')
    function getAlertId(item) {
      return item.RuleID || item.VulnerabilityID || item.test_name || "Unknown";
    }

    // פונקציה אחידה לאיתור שורה בקובץ (אם יש)
    function getLine(item) {
      return item.StartLine || item.Location?.StartLine || item.Line || item.line_number || "none";
    }

    // ממפים וממיינים
    const sortedFindings = combinedFindings
      .map(item => ({
        ...item,
        severity: getSeverity(item),
        alertId: getAlertId(item),
        line: getLine(item),
      }))
      .sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

    return Promise.resolve(
      sortedFindings.map(item => {
        const label = `${item.alertId}: Line ${item.line}`;
        const desc = item.Description || item.Title || item.Message || item.issue_text || "No description";
        const severity = item.severity || item.issue_severity;
        const filePath = item.File || item.Path || item.filename|| item.Location?.Path || "";
        item.FilePath = filePath;
        const alertItem = new vscode.TreeItem(
          label,
          vscode.TreeItemCollapsibleState.None
        );

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
