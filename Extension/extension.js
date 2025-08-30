const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const chartImages = {};
const { runFullContainerScan } = require("./utils/containerReport");
const { initSecretScanner, showDiagnostics } = require("./utils/secretDetection");
const { generatePDFReport } = require("./add-pdf/reportGenerator");
const { runBanditScan } = require("./utils/sast");
const { showDashboard, getChartImages } = require("./utils/showDashboard");
const { 
  openAlertBanner, 
  setCurrentFindings: setCurrentFindingsFromBanner, 
  setCurrentTrivyFindings: setTrivyFromBanner, 
  setCurrentBanditFindings: setBanditFromBanner, 
  setCurrentContainerFindings: setContainerFromBanner 
} = require('./utils/openAlertBanner');

const { 
  AlertsProvider, 
  setCurrentFindings: setCurrentFindingsFromAlerts, 
  setCurrentTrivyFindings: setTrivyFromAlerts, 
  setCurrentContainerFindings: setContainerFromAlerts, 
  setCurrentBanditFindings: setBanditFromAlerts 
} = require("./utils/alertsProvider");

const { initSCA, showScaDiagnostics, attachFilePathToTrivyFindings, attachLinesToTrivy, registerScaInlineFixes,} = require("./utils/sca");


let alertsProvider;
let currentFindings = [];
let currentTrivyFindings = [];
let currentContainerFindings = [];
let currentBanditFindings = [];

function getTempScanDir() {
  const workspacePath =
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || "default";
  return path.join(os.tmpdir(), "devsecode", path.basename(workspacePath));
}

function clearOldReports() {
  const tempDir = getTempScanDir();
  const filesToDelete = [
    "gitleaks_report.json",
    "trivy_report.json",
    "bandit_report.json",
    "ContainerScanning_Report.json",
  ];

  for (const f of filesToDelete) {
    const fullPath = path.join(tempDir, f);
    if (fs.existsSync(fullPath)) {
      try {
        fs.unlinkSync(fullPath);
        console.log(`🧹 Deleted old report: ${fullPath}`);
      } catch (err) {
        console.warn(`⚠️ Failed to delete ${fullPath}:`, err);
      }
    }
  }
}


function activate(context) {
  alertsProvider = new AlertsProvider(context);
  vscode.window.registerTreeDataProvider("devsecodeAlerts", alertsProvider);

  initSecretScanner(context, getTempScanDir, alertsProvider);
  initSCA(context, getTempScanDir, alertsProvider);
  registerScaInlineFixes(context);

  let disposable = vscode.commands.registerCommand(
    "DevSecode.runScan",
    async (uri) => {
      clearOldReports();
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

                  vscode.window.showInformationMessage("Opening dashboard...");

                  cp.exec(
                    trivyCommand,
                    { maxBuffer: 1024 * 1000 },
                    async (trivyErr) => {
                      if (trivyErr) {
                        vscode.window.showErrorMessage(
                          "Trivy scan failed. Ensure Trivy is installed and configured properly."
                        );
                        return resolve();
                      }

                      attachFilePathToTrivyFindings(trivyReportPath);
                      attachLinesToTrivy(trivyReportPath, path.join(rootPath, "requirements.txt"));
                      showScaDiagnostics(trivyReportPath, path.join(rootPath, "requirements.txt"));

                      if (!fs.existsSync(trivyReportPath)) {
                        vscode.window.showInformationMessage(
                          "No Trivy report created. Possibly no vulnerabilities or an error occurred."
                        );
                        return resolve();
                      }

                      let trivyData = [];
                      try {
                        const trivyRaw = fs.readFileSync(
                          trivyReportPath,
                          "utf8"
                        );
                        trivyData = JSON.parse(trivyRaw);
                        console.log("✅ Trivy report loaded successfully.");

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

                      currentFindings = findings;
                      setCurrentFindingsFromAlerts(currentFindings);
                      setCurrentFindingsFromBanner(currentFindings);

                      currentTrivyFindings = JSON.parse(fs.readFileSync(trivyReportPath, "utf8"));
                      setTrivyFromAlerts(currentTrivyFindings);
                      setTrivyFromBanner(currentTrivyFindings);

                      // Ask for container image or "all"
                      const containerImage = await vscode.window.showInputBox({
                        placeHolder:
                          "e.g., nginx:1.25-alpine or type 'all' to scan every image in repo",
                        prompt:
                          "Enter the Docker image you want to scan (or 'all' to scan every image referenced in your project)",
                      });

                      if (containerImage) {
                        const targets =
                          containerImage.trim().toLowerCase() === "all"
                            ? collectImages(rootPath)
                            : [containerImage];

                        const reports = [];
                        for (const img of targets) {
                          vscode.window.showInformationMessage(
                            `🔍 Scanning ${img}...`
                          );
                          const rpt = await runFullContainerScan(
                            img,
                            rootPath,
                            trivyConfigToUse
                          );
                          reports.push(rpt);
                        }

                        // Combine and write once
                        const combined = {
                          generated_at: new Date().toISOString(),
                          scanned_images: reports.map(
                            (r) => r.metadata.ArtifactName
                          ),
                          reports,
                        };
                        const outFile = path.join(
                          getTempScanDir(),
                          "ContainerScanning_Report.json"
                        );
                        fs.writeFileSync(
                          outFile,
                          JSON.stringify(combined, null, 2)
                        );
                        vscode.window.showInformationMessage(
                          "📄 ContainerScanning_Report.json generated!"
                        );

                        try {
                          currentContainerFindings = JSON.parse(fs.readFileSync(outFile, "utf8"));
                        } catch (e) {
                          currentContainerFindings = [];
                        }

                        setContainerFromAlerts(currentContainerFindings);
                        setContainerFromBanner(currentContainerFindings);

                      }

                      currentBanditFindings = await runBanditScan(rootPath, getTempScanDir(), context) || [];
                      setBanditFromAlerts(currentBanditFindings);
                      setBanditFromBanner(currentBanditFindings);


                      vscode.commands.registerCommand(
                        "DevSecode.showDashboard",
                        () => {
                          showDashboard(context, currentFindings, currentTrivyFindings, currentBanditFindings, currentContainerFindings);
                        }
                      );

                      showDashboard(context, currentFindings, currentTrivyFindings, currentBanditFindings, currentContainerFindings);
                      alertsProvider.refresh();
                      return resolve();

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

  async function runContainerScan(imageName, rootPath, trivyConfigToUse) {
    const safeName = imageName.replace(/[^a-zA-Z0-9_.-]/g, "_");
    const imageReportPath = path.join(rootPath, `trivy_image_${safeName}.json`);
    const trivyImageCommand = trivyConfigToUse
      ? `trivy image "${imageName}" --config "${trivyConfigToUse}" --format json --output "${imageReportPath}"`
      : `trivy image "${imageName}" --format json --output "${imageReportPath}"`;

    return new Promise((resolve) => {
      cp.exec(trivyImageCommand, { maxBuffer: 1024 * 1000 }, (err) => {
        if (err) {
          vscode.window.showErrorMessage(
            `Container scan failed for ${imageName}. Ensure Trivy is installed and Docker is running.`
          );
          return resolve();
        }

        let containerData = {};
        try {
          containerData = JSON.parse(fs.readFileSync(imageReportPath, "utf8"));
          vscode.window.showInformationMessage(
            `✅ Container scan for ${imageName} completed.`
          );
        } catch {
          vscode.window.showWarningMessage(
            `⚠️ Failed to parse Trivy report for ${imageName}.`
          );
        }

        currentContainerFindings =
          containerData.Results?.flatMap((r) => r.Vulnerabilities || []) || [];
        currentContainerFindings._rawImageReport = containerData;
        resolve();
      });
    });
  }
  context.subscriptions.push(disposable);

  let openAlertBannerCommand = vscode.commands.registerCommand(
    "DevSecode.openAlertBanner",
    (item) => {
      openAlertBanner(item);
    }
  );
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
      let gitleaksFindings = [];
      if (fs.existsSync(findingsPath)) {
        try {
          gitleaksFindings = JSON.parse(fs.readFileSync(findingsPath, "utf-8"));
        } catch (e) {
          vscode.window.showWarningMessage("⚠️ Failed to parse gitleaks_report.json; continuing without findings.");
        }
      }
      
      

      const trivyPath = path.join(getTempScanDir(), "trivy_report.json");
      const banditPath = path.join(getTempScanDir(), "bandit_report.json");

      let trivyFindings = [];
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
      const folders = vscode.workspace.workspaceFolders || [];
      const wsFolder = folders.length ? folders[0] : null;
      const wsPath   = wsFolder ? wsFolder.uri.fsPath : (config.workspacePath || undefined);
      
      const projName = (wsFolder && wsFolder.name)
        ? wsFolder.name
        : (wsPath ? path.basename(wsPath) : 'project');
      
      config.workspacePath = config.workspacePath || wsPath;
      config.projectName   = config.projectName   || projName;
     
      // if you followed my earlier step to export getChartImages():

      const images = (typeof getChartImages === 'function') ? getChartImages() : {};
      // Load Container scan (Trivy image) findings if the file exists
        const containerPath = path.join(getTempScanDir(), "ContainerScanning_Report.json");
        let containerFindings = [];
        if (fs.existsSync(containerPath)) {
          try {
            const raw = JSON.parse(fs.readFileSync(containerPath, "utf8"));
            if (Array.isArray(raw)) {
              // flat list
              containerFindings = raw;
            } else if (Array.isArray(raw?.Results)) {
              // standard Trivy image schema
              containerFindings = raw.Results.flatMap(r =>
                Array.isArray(r.Vulnerabilities) ? r.Vulnerabilities : []
              );
            } else if (Array.isArray(raw?.Vulnerabilities)) {
              // some tools dump at top-level
              containerFindings = raw.Vulnerabilities;
            }
          } catch (e) {
            vscode.window.showWarningMessage("⚠️ Failed to parse ContainerScanning_Report.json; continuing without container results.");
          }
        }


      const reportPath = await generatePDFReport(
        gitleaksFindings, 
        config,
        { trivyFindings, banditFindings, containerFindings },
        images
      );

      // ✅ פתיחת הדוח לאחר יצירתו
      vscode.window
        .showInformationMessage(
          "✅ PDF report generated successfully.",
          "Open Report"
        )
        .then(async (selection) => {
          if (selection === "Open Report") {
            try {
              vscode.env.openExternal(vscode.Uri.file(reportPath));
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

function deactivate() { }

module.exports = {
  activate,
  deactivate,
};