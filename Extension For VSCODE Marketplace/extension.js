const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

const { generatePDFReport } = require("./add-pdf/reportGenerator");
const { getFixedVersionFromOSV } = require("./utils/osvApiHelper");

// const { runDastScan } = require("./dastScan");
let alertsProvider;
let currentFindings = [];
let currentTrivyFindings = [];
let currentBanditFindings = [];

function getTempScanDir() {
  const workspacePath =
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || "default";
  return path.join(os.tmpdir(), "devsecode", path.basename(workspacePath));
}

function activate(context) {
  alertsProvider = new AlertsProvider(context);
  vscode.window.registerTreeDataProvider("devsecodeAlerts", alertsProvider);

  scaDiagnostics = vscode.languages.createDiagnosticCollection("sca");
  context.subscriptions.push(scaDiagnostics);

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

      const reportPath = path.join(getTempScanDir(), "gitleaks_report.json");
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

        const trivyReportPath = path.join(
          getTempScanDir(),
          "trivy_report.json"
        ); //Json מוסתר
        //const trivyReportPath = path.join(rootPath, "trivy_report.json");
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
              const tempDir = getTempScanDir();
              if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
              }
              cp.exec(
                command,
                { maxBuffer: 1024 * 1000 },
                (err, stdout, stderr) => {
                  console.log("📥 Gitleaks STDOUT:", stdout);
                  console.log("📤 Gitleaks STDERR:", stderr);
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
                    showDiagnostics(findings, context);
                  }

                  vscode.window.showInformationMessage(
                    "Secret Scan complete. Opening dashboard..."
                  );

                  cp.exec(
                    trivyCommand,
                    { maxBuffer: 1024 * 1000 },
                    async (trivyErr) => {
                      if (trivyErr) {
                        vscode.window.showErrorMessage(
                          "Trivy scan failed. Ensure Trivy is installed and configured properly."
                        );
                        return;
                      }

                      attachFilePathToTrivyFindings(trivyReportPath);

                      if (!fs.existsSync(trivyReportPath)) {
                        vscode.window.showInformationMessage(
                          "No Trivy report created. Possibly no vulnerabilities or an error occurred."
                        );
                        return;
                      }

                      let trivyData = [];
                      try {
                        const trivyRaw = fs.readFileSync(
                          trivyReportPath,
                          "utf8"
                        );
                        trivyData = JSON.parse(trivyRaw);
                        console.log("✅ Trivy report loaded successfully.");

                        // ✅ הוספת מספרי שורות ל־Vulnerabilities
                        attachLinesToTrivy(
                          trivyReportPath,
                          path.join(rootPath, "requirements.txt")
                        );
                      } catch (err) {
                        vscode.window.showWarningMessage(
                          "⚠️ Failed to parse trivy_report.json."
                        );
                        console.warn("Trivy parsing error:", err);
                      }

                      // 💡 אתה יכול להעביר את הנתונים לדאשבורד או להוסיף אותם ל-alertsProvider אם צריך

                      vscode.window.showInformationMessage(
                        "Trivy SCA scan completed successfully."
                      );

                      try {
                        currentTrivyFindings = JSON.parse(
                          fs.readFileSync(trivyReportPath, "utf8")
                        );
                      } catch (e) {
                        currentTrivyFindings = [];
                      }

                      // Ask for container image or "all"
                      const containerImage = await vscode.window.showInputBox({
                        placeHolder:
                          "e.g., nginx:1.25-alpine   •   or type 'all' to scan every image in repo",
                        prompt:
                          "Enter the Docker image you want to scan (or 'all' to scan every image referenced in your project)",
                      });

                      if (containerImage) {
                        if (containerImage.trim().toLowerCase() === "all") {
                          const images = collectImages(rootPath);
                          if (images.length === 0) {
                            vscode.window.showWarningMessage(
                              "No container images found in repository files."
                            );
                          } else {
                            for (const img of images) {
                              const {
                                runFullContainerScan,
                              } = require("./utils/containerReport");

                              await runFullContainerScan(
                                containerImage,
                                rootPath,
                                trivyConfigToUse,
                                null // אין לנו requirements.txt, אנחנו מחפשים בתוך Dockerfile
                              );

                              vscode.window.showInformationMessage(
                                "📄 ContainerScanning_Report.json generated!"
                              );
                            }
                          }
                        } else {
                          const {
                            runFullContainerScan,
                          } = require("./utils/containerReport");

                          await runFullContainerScan(
                            containerImage,
                            rootPath,
                            trivyConfigToUse,
                            null
                          );

                          vscode.window.showInformationMessage(
                            "📄 ContainerScanning_Report.json generated!"
                          );
                        }
                      }
                      const banditReportPath = path.join(
                        getTempScanDir(),
                        "bandit_report.jsonn"
                      ); // Json מוסתר
                      // const banditReportPath = path.join(
                      //   rootPath,
                      //   "bandit_report.json"
                      // );
                      const banditCommand = `bandit -r "${rootPath}" --exclude "${rootPath}/node_modules,${rootPath}/venv" -f json -o "${banditReportPath}"`;

                      const semgrepReportPath = path.join(
                        getTempScanDir(),
                        "semgrep_report.json"
                      ); // Json מוסתר

                      // const semgrepReportPath = path.join(
                      //   rootPath,
                      //   "semgrep_report.json"
                      // );
                      const semgrepCommand = `semgrep --config auto --json --output "${semgrepReportPath}" "${rootPath}"`;

                      const util = require("util");
                      const exec = util.promisify(cp.exec);

                      (async () => {
                        try {
                          await exec(semgrepCommand, {
                            maxBuffer: 1024 * 1000,
                          });
                          vscode.window.showInformationMessage(
                            "✅ Semgrep scan completed."
                          );
                        } catch (e) {
                          vscode.window.showWarningMessage(
                            "❌ Semgrep scan failed."
                          );
                          console.error("Semgrep error:", e.stderr || e);
                        }

                        try {
                          await exec(banditCommand, { maxBuffer: 1024 * 1000 });
                          vscode.window.showInformationMessage(
                            "✅ Bandit scan completed."
                          );
                        } catch (e) {
                          console.error("Bandit error:", e.stderr || e);
                        }

                        let banditData = [];

                        try {
                          const banditRaw = fs.readFileSync(
                            banditReportPath,
                            "utf8"
                          );
                          banditData = JSON.parse(banditRaw);
                          console.log("✅ Bandit report loaded successfully.");
                        } catch (err) {
                          vscode.window.showWarningMessage(
                            "⚠️ Failed to parse bandit_report.json."
                          );
                          console.warn("Bandit parsing error:", err);
                        }

                        vscode.window.showInformationMessage(
                          "Bandit scan completed successfully."
                        );

                        try {
                          currentBanditFindings = banditData.results || [];
                        } catch (e) {
                          currentBanditFindings = [];
                        }

                        //  await runDastScan(rootPath);
                        vscode.commands.registerCommand(
                          "DevSecode.showDashboard",
                          () => {
                            showDashboard(context, findings);
                          }
                        );

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

      // 🎯 רישום hover על requirements.txt
      context.subscriptions.push(
        vscode.languages.registerHoverProvider(
          { pattern: "**/requirements.txt" },
          {
            async provideHover(document, position) {
              const lineText = document.lineAt(position.line).text;

              const match = lineText.match(/^([a-zA-Z0-9_\-]+)==([\d\.]+)$/);
              if (!match) return;

              const packageName = match[1];
              const version = match[2];

              try {
                const fixes = await getFixedVersionFromOSV(
                  packageName,
                  version
                );

                const cleanFixes = Array.from(
                  new Set(fixes.filter((v) => /^\d+\.\d+(\.\d+)?$/.test(v)))
                );

                if (cleanFixes.length > 0) {
                  return new vscode.Hover(
                    `⚠️ **${packageName}==${version}** is vulnerable.\n\n💡 Recommended versions:\n- ${cleanFixes.join(
                      "\n- "
                    )}`
                  );
                }
              } catch (err) {
                console.error("❌ Hover error:", err);
              }

              return; // אין תיקונים => לא מציגים כלום
            },
          }
        )
      );

      context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
          { pattern: "**/requirements.txt" },
          {
            async provideCodeActions(document, range, context) {
              const actions = [];

              const lineText = document.lineAt(range.start.line).text;
              const match = lineText.match(/^([a-zA-Z0-9_\-]+)==([\d\.]+)$/);
              if (!match) return;

              const packageName = match[1];
              const version = match[2];

              const fixes = await getFixedVersionFromOSV(packageName, version);
              if (!fixes || fixes.length === 0) return;

              const cleanFixes = Array.from(
                new Set(fixes.filter((v) => /^\d+\.\d+(\.\d+)?$/.test(v)))
              );

              if (cleanFixes.length === 0) return;

              const diagnostic = new vscode.Diagnostic(
                range,
                `❌ Vulnerable package: ${packageName}==${version}`,
                vscode.DiagnosticSeverity.Error
              );
              diagnostic.source = "SCA";

              // בדיקה אם כבר קיים, כמו קודם:
              const existing = scaDiagnostics.get(document.uri) || [];
              const alreadyExists = existing.some(
                (d) =>
                  d.range.start.line === diagnostic.range.start.line &&
                  d.message === diagnostic.message
              );
              if (!alreadyExists) {
                const updated = [...existing, diagnostic];
                scaDiagnostics.set(document.uri, updated);
              }

              const fix = new vscode.CodeAction(
                `🛠 Update ${packageName} to a safer version`,
                vscode.CodeActionKind.QuickFix
              );
              fix.command = {
                title: "Choose safe version",
                command: "devsecode.updatePackageVersion",
                arguments: [document, range, packageName, version, cleanFixes],
              };

              return [fix];
            },
          },
          {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
          }
        )
      );

      context.subscriptions.push(
        vscode.commands.registerCommand(
          "devsecode.updatePackageVersion",
          async (document, range, packageName, currentVersion, fixes) => {
            const version = await vscode.window.showQuickPick(fixes, {
              placeHolder: `Choose a secure version for ${packageName}`,
            });

            if (!version) return;

            const newLine = `${packageName}==${version}`;
            const edit = new vscode.WorkspaceEdit();
            const fullRange = document.lineAt(range.start.line).range;

            await edit.replace(document.uri, fullRange, newLine);
            await vscode.workspace.applyEdit(edit);

            vscode.window.showInformationMessage(
              `✅ Updated ${packageName} from ${currentVersion} to ${version}`
            );

            vscode.window.showWarningMessage(
              `⚠️ Make sure to review any code that uses '${packageName}' (e.g., 'import ${packageName}') to ensure compatibility with version ${version}.`
            );

            scaDiagnostics.delete(document.uri);
          }
        )
      );
    }
  );

  // 🔒 DAST integration directly embedded into DevSecode Extension
  // This is a standalone function based on the logic of dast.py, rewritten in Node.js to be part of the extension.

  /* const runDastScan = async (rootPath) => {
  const vscode = require("vscode");
  const path = require("path");
  const fs = require("fs");
  const axios = require("axios");

  const ZAP_API = "http://127.0.0.1:8080";
  const target = "http://localhost:5000";

  vscode.window.showInformationMessage("🔍 Starting embedded DAST scan...");

  try {
    // Spidering
    const spiderStart = await axios.get(`${ZAP_API}/JSON/spider/action/scan/`, {
      params: { url: target }
    });
    const scanId = spiderStart.data.scan;

    let status = "0";
    while (status !== "100") {
      await new Promise((r) => setTimeout(r, 2000));
      const progress = await axios.get(`${ZAP_API}/JSON/spider/view/status/`, {
        params: { scanId }
      });
      status = progress.data.status;
    }

    // Wait for passive scan
    let recordsToScan = 1;
    while (recordsToScan > 0) {
      await new Promise((r) => setTimeout(r, 2000));
      const scanView = await axios.get(`${ZAP_API}/JSON/pscan/view/recordsToScan/`);
      recordsToScan = parseInt(scanView.data.recordsToScan);
    }

    // Active scan
    const ascanStart = await axios.get(`${ZAP_API}/JSON/ascan/action/scan/`, {
      params: { url: target }
    });
    const ascanId = ascanStart.data.scan;

    let ascanStatus = "0";
    while (ascanStatus !== "100") {
      await new Promise((r) => setTimeout(r, 5000));
      const progress = await axios.get(`${ZAP_API}/JSON/ascan/view/status/`, {
        params: { scanId: ascanId }
      });
      ascanStatus = progress.data.status;
    }

    // Fetch alerts
    const alertRes = await axios.get(`${ZAP_API}/JSON/core/view/alerts/`);
    const alerts = alertRes.data.alerts;

    const outputDir = path.join(rootPath, "UI", "json_output");
    fs.mkdirSync(outputDir, { recursive: true });

    const outputPath = path.join(outputDir, "zap_scan_results.json");
    fs.writeFileSync(outputPath, JSON.stringify(alerts, null, 2));

    vscode.window.showInformationMessage("✅ DAST scan completed and report saved.");
  } catch (err) {
    vscode.window.showWarningMessage("⚠️ DAST scan failed.");
    console.error("DAST error:", err);
  }
};

module.exports.runDastScan = runDastScan;
*/

  vscode.languages.registerCodeActionsProvider("*", {
    provideCodeActions(document, range, context) {
      const actions = [];

      for (const diagnostic of context.diagnostics) {
        if (diagnostic.source === "Secret Scanner") {
          const fix = new vscode.CodeAction(
            "🛡 Remove hardcoded secret",
            vscode.CodeActionKind.QuickFix
          );
          fix.diagnostics = [diagnostic];
          fix.command = {
            title: "Remove and explain",
            command: "devsecode.removeSecretLine",
            arguments: [document, diagnostic.range],
          };
          actions.push(fix);
        }
      }

      return actions;
    },
  });

  function collectImages(rootPath) {
    const images = new Set();

    const add = (img) => {
      if (img && !img.startsWith("${")) images.add(img.trim());
    };

    // 1. All *.yaml / *.yml (docker-compose, k8s)
    glob
      .sync("**/*.{yaml,yml}", { cwd: rootPath, nodir: true })
      .forEach((f) => {
        const text = fs.readFileSync(path.join(rootPath, f), "utf8");
        const re = /image:\s*["']?([^"'\s#]+)(?=["'\s#]|$)/gi;
        let m;
        while ((m = re.exec(text))) add(m[1]);
      });

    // 2. Any file named *Dockerfile*  – look for BOTH  “FROM …” and “image: …”
    glob.sync("**/Dockerfile*", { cwd: rootPath, nodir: true }).forEach((f) => {
      const text = fs.readFileSync(path.join(rootPath, f), "utf8");
      text.split(/\r?\n/).forEach((line) => {
        const from = line.match(/^\s*FROM\s+([^\s]+).*$/i);
        if (from) add(from[1]);

        const img = line.match(/image:\s*["']?([^"'\s#]+)(?=["'\s#]|$)/i);
        if (img) add(img[1]);
      });
    });

    return Array.from(images);
  }
  context.subscriptions.push(disposable);

  let openAlertBannerCommand = vscode.commands.registerCommand(
    "DevSecode.openAlertBanner",
    (item) => {
      openAlertBanner(item);
    }
  );
  const removeSecretCommand = vscode.commands.registerCommand(
    "devsecode.removeSecretLine",
    async (document, range) => {
      const fullLineRange = new vscode.Range(
        new vscode.Position(range.start.line, 0),
        new vscode.Position(range.start.line + 1, 0)
      );

      const lineText = document.getText(fullLineRange);

      const edit = new vscode.WorkspaceEdit();
      edit.delete(document.uri, fullLineRange);
      await vscode.workspace.applyEdit(edit);

      const choice = await vscode.window.showWarningMessage(
        "⚠️ The line was removed because it contained a hardcoded secret.\n" +
          "To securely manage secrets in your code:\n" +
          "✅ Use environment variables (e.g., process.env.MY_SECRET)\n" +
          "✅ Or a secure secret manager (e.g., GitHub Secrets, AWS Secrets Manager, Vault)",
        "Undo removal"
      );

      if (choice === "Undo removal") {
        const undoEdit = new vscode.WorkspaceEdit();
        undoEdit.insert(
          document.uri,
          new vscode.Position(range.start.line, 0),
          lineText
        );
        await vscode.workspace.applyEdit(undoEdit);
        vscode.window.showInformationMessage("✅ Secret line restored.");
      }
    }
  );
  context.subscriptions.push(removeSecretCommand);

  context.subscriptions.push(removeSecretCommand);

  context.subscriptions.push(openAlertBannerCommand);
  const generatePdfCommand = vscode.commands.registerCommand(
    "devsecode.generateCustomPDF",
    async () => {
      // 🟩 בחירת חומרות
      const severityOptions = await vscode.window.showQuickPick(
        ["Critical", "High", "Medium", "Low"],
        {
          canPickMany: true,
          placeHolder: "Select severity levels to include",
        }
      );

      if (!severityOptions || severityOptions.length === 0) {
        vscode.window.showErrorMessage(
          "❌ Please select at least one severity level."
        );
        return;
      }

      // 🟩 בחירת מיון
      const sortOrder = await vscode.window.showQuickPick(
        ["Severity", "Line Number"],
        {
          placeHolder: "Select how to sort the report",
        }
      );

      if (!sortOrder) {
        vscode.window.showErrorMessage(
          "❌ Please select a sort order for the report."
        );
        return;
      }

      const sortKey = sortOrder === "Line Number" ? "line" : "severity";

      // 🟩 איתור תיקיית העבודה
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showErrorMessage("❌ No workspace folder found.");
        return;
      }
      const workspacePath = workspaceFolders[0].uri.fsPath;

      // 🟩 קונפיגורציית הדוח
      const config = {
        selectedSeverities: severityOptions, // ✅ רמות חומרה שנבחרו
        sortBy: sortKey,
        workspacePath: workspacePath,
      };

      // שמירה מקומית של config (לא חובה, רק לצורך פיתוח)
      const configPath = path.join(__dirname, "add-pdf", "report.config.json");
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

      // 🟩 טוען את הדוח JSON
      const findingsPath = path.join(getTempScanDir(), "gitleaks_report.json");
      if (!fs.existsSync(findingsPath)) {
        vscode.window.showErrorMessage(
          "❌ Could not find gitleaks_report.json in UI folder."
        );
        return;
      }

      const trivyPath = path.join(getTempScanDir(), "trivy_report.json");
      const banditPath = path.join(getTempScanDir(), "bandit_report.json");
      const semgrepPath = path.join(getTempScanDir(), "semgrep_report.json");

      // const trivyPath = path.join(workspacePath, "trivy_report.json");
      // const semgrepPath = path.join(workspacePath, "semgrep_report.json");
      // const banditPath = path.join(workspacePath, "bandit_report.json");

      let trivyFindings = [];
      let semgrepFindings = [];
      let banditFindings = [];

      if (fs.existsSync(trivyPath)) {
        try {
          trivyFindings = JSON.parse(fs.readFileSync(trivyPath, "utf-8"));
        } catch (e) {
          vscode.window.showWarningMessage(
            "⚠️ Failed to load trivy_report.json."
          );
        }
      }

      if (fs.existsSync(semgrepPath)) {
        try {
          semgrepFindings = JSON.parse(fs.readFileSync(semgrepPath, "utf-8"));
        } catch (e) {
          vscode.window.showWarningMessage(
            "⚠️ Failed to load semgrep_report.json."
          );
        }
      }

      if (fs.existsSync(banditPath)) {
        try {
          banditFindings = JSON.parse(fs.readFileSync(banditPath, "utf-8"));
        } catch (e) {
          vscode.window.showWarningMessage(
            "⚠️ Failed to load bandit_report.json."
          );
        }
      }
      let findings;
      try {
        const findingsRaw = fs.readFileSync(findingsPath, "utf-8");
        findings = JSON.parse(findingsRaw);
      } catch (e) {
        vscode.window.showErrorMessage(
          "❌ Failed to read or parse gitleaks_report.json."
        );
        return;
      }

      const reportPath = await generatePDFReport(findings, config, {
        trivyFindings,
        semgrepFindings,
        banditFindings,
      });
      // ✅ פתיחת הדוח לאחר יצירתו
      vscode.window
        .showInformationMessage(
          "✅ PDF report generated successfully.",
          "Open Report"
        )
        .then(async (selection) => {
          if (selection === "Open Report") {
            try {
              const open = await import("open").then((mod) => mod.default);
              await open(reportPath);
            } catch (err) {
              vscode.window.showErrorMessage(
                `❌ Failed to open the report: ${err.message}`
              );
            }
          }
        });
    }
  );

  context.subscriptions.push(generatePdfCommand);

  // 🟩 כפתור בשורת הסטטוס
  const pdfStatusBarButton = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  pdfStatusBarButton.command = "devsecode.generateCustomPDF";
  pdfStatusBarButton.text = "$(file-pdf) Generate PDF Report";
  pdfStatusBarButton.tooltip = "Click to generate a custom PDF report";
  pdfStatusBarButton.show();

  context.subscriptions.push(pdfStatusBarButton);

  const dashboardStatusBarButton = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    99
  );
  dashboardStatusBarButton.command = "DevSecode.showDashboard";
  dashboardStatusBarButton.text = "$(dashboard) Open Dashboard";
  dashboardStatusBarButton.tooltip = "Click to open the DevSecode Dashboard";
  dashboardStatusBarButton.show();

  context.subscriptions.push(dashboardStatusBarButton);
}

function watchGitleaksReport(context) {
  // const reportPath = path.join(
  //   context.extensionPath,
  //   "UI",
  //   "gitleaks_report.json"
  // );
  const reportPath = path.join(getTempScanDir(), "gitleaks_report.json");

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

function attachFilePathToTrivyFindings(trivyReportPath) {
  const fs = require("fs");

  try {
    const raw = fs.readFileSync(trivyReportPath, "utf-8");
    const json = JSON.parse(raw);

    if (json.Results) {
      json.Results.forEach((result) => {
        const workspacePath =
          vscode.workspace.workspaceFolders?.[0].uri.fsPath || "";
        const targetFile = result.Target;
        const absolutePath = path.join(workspacePath, targetFile);

        if (result.Vulnerabilities) {
          result.Vulnerabilities.forEach((vuln) => {
            vuln.file_path = absolutePath;
          });
        }
      });
    }

    fs.writeFileSync(trivyReportPath, JSON.stringify(json, null, 2));
    console.log("✅ file_path added successfully to each vulnerability.");
  } catch (err) {
    console.error("❌ Failed to process Trivy report:", err);
  }
}

function attachLinesToTrivy(trivyReportPath, requirementsPath) {
  if (!fs.existsSync(trivyReportPath) || !fs.existsSync(requirementsPath)) {
    console.warn("Trivy report or requirements.txt not found.");
    return;
  }

  const report = JSON.parse(fs.readFileSync(trivyReportPath, "utf8"));
  const lines = fs.readFileSync(requirementsPath, "utf8").split("\n");

  const lineMap = {};
  lines.forEach((line, idx) => {
    const pkg = line.split("==")[0].trim().toLowerCase();
    if (pkg) {
      lineMap[pkg] = idx + 1;
    }
  });

  for (const result of report.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      const pkg = vuln.PkgName?.toLowerCase();
      if (pkg && lineMap[pkg]) {
        vuln.line_number = lineMap[pkg];
      }
    }
  }

  fs.writeFileSync(trivyReportPath, JSON.stringify(report, null, 2));
  console.log("✅ Line numbers added to Trivy report.");
}

function showDiagnostics(findings, context) {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("secretScanner");
  context.subscriptions.push(diagnosticCollection); // ✅ חובה!

  const diagnosticsMap = new Map();

  findings.forEach((finding) => {
    const fileUri = vscode.Uri.file(finding.File);
    const line = finding.StartLine ? finding.StartLine - 1 : 0;
    const range = new vscode.Range(
      new vscode.Position(line, 0),
      new vscode.Position(line, 100)
    );

    const message = `🚨 Hardcoded Secret Detected
• Rule: ${finding.RuleID}
• Description: ${finding.Description || "Potential secret detected."}
${finding.redacted ? "• Secret was redacted" : ""}

⚠️ Secrets should NEVER be committed to source code.
Use environment variables or secret managers instead.`;

    const diagnostic = new vscode.Diagnostic(
      range,
      message,
      vscode.DiagnosticSeverity.Error
    );
    diagnostic.source = "Secret Scanner";

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
    path.join(context.extensionPath, "UI", "devsecode_logo.png")
  );
  const imageUri = panel.webview.asWebviewUri(imagePath);

  // 🆕 קריאת הדוח של Trivy
  const trivyReportPath = path.join(getTempScanDir(), "trivy_report.json");

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
  const banditReportPath = path.join(getTempScanDir(), "bandit_report.json");

  let banditData = null;
  if (fs.existsSync(banditReportPath)) {
    try {
      const rawBandit = fs.readFileSync(banditReportPath, "utf8");
      banditData = JSON.parse(rawBandit);
    } catch (err) {
      vscode.window.showWarningMessage(
        "⚠️ Failed to parse bandit_report.json."
      );
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
  const vscode = require("vscode");
  const path = require("path");
  const fs = require("fs");

  const id =
    alertItem.RuleID ||
    alertItem.VulnerabilityID ||
    alertItem.test_name ||
    "Unknown";
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
    if (
      typeof currentTrivyFindings !== "undefined" &&
      currentTrivyFindings.Results
    ) {
      reportData = currentTrivyFindings.Results.flatMap(
        (result) => result.Vulnerabilities || []
      );
    }
  } else if (
    alertItem.test_name ||
    alertItem.issue_text ||
    alertItem.issue_severity
  ) {
    // Bandit
    if (
      typeof currentBanditFindings !== "undefined" &&
      Array.isArray(currentBanditFindings)
    ) {
      reportData = currentBanditFindings;
    }
  } else {
    // Gitleaks
    if (typeof currentFindings !== "undefined") {
      reportData = currentFindings;
    }
  }

  // שים לב, לשלב גם נתיב קובץ של האלרט אם קיים (ל-Gitleaks או Trivy)
  const filePath =
    alertItem.FilePath ||
    (alertItem.Location && alertItem.Location.Path) ||
    alertItem.filename ||
    "";
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
    (message) => {
      if (message.command === "goToLine") {
        const { filePath, lineNumber } = message;
        if (filePath && lineNumber) {
          const uri = vscode.Uri.file(filePath);
          vscode.workspace.openTextDocument(uri).then((doc) => {
            vscode.window.showTextDocument(doc, {
              selection: new vscode.Range(
                new vscode.Position(lineNumber - 1, 0),
                new vscode.Position(lineNumber - 1, Number.MAX_SAFE_INTEGER)
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
    const combinedFindings = [
      ...(currentFindings || []),
      ...(currentTrivyFindings?.Results?.flatMap(
        (r) => r.Vulnerabilities || []
      ) || []),
      ...(currentBanditFindings || []),
    ];

    if (combinedFindings.length === 0) {
      return Promise.resolve([]);
    }

    const severityRank = {
      Critical: 0,
      High: 1,
      Medium: 2,
      Low: 3,
      Unknown: 4,
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
      return (
        item.StartLine ||
        item.Location?.StartLine ||
        item.Line ||
        item.line_number ||
        "none"
      );
    }

    // ממפים וממיינים
    const sortedFindings = combinedFindings
      .map((item) => ({
        ...item,
        severity: getSeverity(item),
        alertId: getAlertId(item),
        line: getLine(item),
      }))
      .sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

    return Promise.resolve(
      sortedFindings.map((item) => {
        const label = `${item.alertId}: Line ${item.line}`;
        const desc =
          item.Description ||
          item.Title ||
          item.Message ||
          item.issue_text ||
          "No description";
        const severity = item.severity || item.issue_severity;
        const filePath =
          item.File || item.Path || item.filename || item.Location?.Path || "";
        item.FilePath = filePath;
        const alertItem = new vscode.TreeItem(
          label,
          vscode.TreeItemCollapsibleState.None
        );

        const iconFilename = `${severity.toLowerCase()}_icon.png`;
        alertItem.iconPath = vscode.Uri.file(
          path.join(this.context.extensionPath, "UI", iconFilename)
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
