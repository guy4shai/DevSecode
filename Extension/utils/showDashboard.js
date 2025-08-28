const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const os = require("os");

const chartImages = {};
const { openAlertBanner } = require("./openAlertBanner");

let globalFindings = [];
let globalTrivy = [];
let globalBandit = [];
let globalContainer = [];

function showDashboard(context, findings, currentTrivyFindings = [], currentBanditFindings = [], currentFindings = [], currentContainerFindings = []) {
  const panel = vscode.window.createWebviewPanel(
    "devsecDashboard",
    "DevSecode Dashboard",
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  const htmlPath = path.join(context.extensionPath, "UI", "dashboard.html");
  let html = fs.readFileSync(htmlPath, "utf8");
  console.log("✅ Loaded dashboard.html content length:", html.length);

  const imagePath = vscode.Uri.file(
    path.join(context.extensionPath, "UI", "devsecode_logo.png")
  );
  const imageUri = panel.webview.asWebviewUri(imagePath);

  //Trivy
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

  //Bandit
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

  //Container scanning
  const containerReportPath = path.join(getTempScanDir(), "ContainerScanning_Report.json");
  let containerData = null;
  if (fs.existsSync(containerReportPath)) {
    try {
      const rawContainer = fs.readFileSync(containerReportPath, "utf8");
      const parsed = JSON.parse(rawContainer);

      containerData = {
        summary: parsed.reports?.[0]?.vulnerability_summary || {},
        top_vulnerabilities: parsed.reports?.[0]?.top_vulnerabilities || []
      };

    } catch (err) {
      console.warn("Failed to parse container scan report", err);
    }
  }

  globalFindings = findings || [];
  globalTrivy = currentTrivyFindings || [];
  globalBandit = currentBanditFindings || [];
  globalContainer = currentContainerFindings || [];


  html = html
    .replace('src="./devsecode_logo.png"', `src="${imageUri}"`)
    .replace(
      "</head>",
      `<script>
        const reportData = ${JSON.stringify(findings)};
        const scaData = ${JSON.stringify(trivyData || [])};
        const banditData = ${JSON.stringify(banditData || [])};
        const containerData = ${JSON.stringify(containerData || [])};
      </script></head>`
    );

  console.log("✅ Prepared HTML for webview, length:", html.length);


  panel.webview.html = html;
  console.log("✅ Set webview HTML content.");


  panel.webview.onDidReceiveMessage(async (message) => {
    console.log("📩 Received message from webview:", message);

    if (message.type === "chartImage") {
      chartImages[message.chartId] = {
        image: message.dataUrl,
        legend: message.legend || [],
      };
      console.log(`📊 Got image & legend: ${message.chartId}`);
    }

    //************************************************
    // Vulnerability Chart
    //************************************************

    if (message.type === "vulnerabilityTypeClicked") {
      const clickedType = message.label;

      const detailPanel = vscode.window.createWebviewPanel(
        "vulnerabilityDetail",
        `Vulnerability: ${clickedType}`,
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          localResourceRoots: [
            vscode.Uri.file(path.join(context.extensionPath, "UI")),
          ],
        }
      );

      const htmlPath = path.join(
        context.extensionPath,
        "UI",
        "vulnerabilityChartDetail.html"
      );
      let rawHtml = fs.readFileSync(htmlPath, "utf8");
 
      const allFindings = [
        ...(globalFindings || []),
        ...(globalTrivy?.Results?.flatMap(r => r.Vulnerabilities || []) || []),
        ...(globalBandit || []),
        ...(containerData?.top_vulnerabilities || []),
      ];


      const clickedTypeLower = (clickedType || "").toString().toLowerCase();


      const findingsForType = allFindings.filter((item) => {
        const ruleId = item.RuleID || item.ruleId || "";
        const vulnId = item.VulnerabilityID || "";
        const testName = item.test_name || "";
        const ID = item.ID || "";

        return (
          ruleId.toLowerCase() === clickedTypeLower ||
          vulnId.toLowerCase() === clickedTypeLower ||
          testName.toLowerCase() === clickedTypeLower ||
          ID.toLowerCase() === clickedTypeLower
        );
      });


      function getLine(item) {
        return (
          item.StartLine ||
          item.line_number ||
          item.Line ||
          item.Location?.StartLine ||
          item.location?.start?.line ||
          null
        );
      }

      function getFilePath(item) {
        return (
          item.file ||
          item.File ||
          item.filename ||
          item.file_path ||
          item.FilePath ||
          item.Target ||
          item.Location?.Path ||
          item.location?.file ||
          item.location?.path ||
          null
        );
      }

      const findingsWithLines = findingsForType.map((item) => ({
        ...item,
        line: getLine(item),
        file: getFilePath(item),
      }));

      rawHtml = rawHtml.replace(
        "</head>",
        `<script>
          const selectedVulnerabilityLabel = ${JSON.stringify(clickedType)};
          const occurrences = ${JSON.stringify(findingsWithLines)};
        </script></head>`
      );

      detailPanel.webview.html = rawHtml;

      detailPanel.webview.onDidReceiveMessage(
        (message) => {
          if (message.command === "openAlertBanner" && message.alertItem) {
            openAlertBanner(message.alertItem); 
          }
        },
        undefined,
        context.subscriptions
      );
    }

    //************************************************
    // Severity Chart
    //************************************************

    if (message.type === "severitySliceClicked") {
      const clickedSeverity = message.label;
      const clickedScanner = message.scanner;

      const detailPanel = vscode.window.createWebviewPanel(
        "severityDetail",
        `Severity: ${clickedSeverity}`,
        vscode.ViewColumn.One,
        {
          enableScripts: true,
          localResourceRoots: [
            vscode.Uri.file(path.join(context.extensionPath, "UI")),
          ],
        }
      );

      const htmlPath = path.join(
        context.extensionPath,
        "UI",
        "severityChartDetail.html"
      );
      let rawHtml = fs.readFileSync(htmlPath, "utf8");

      function getScannerName(item) {
        const hasTrivyID = item.VulnerabilityID;
        const hasGitleaksID =
          item.RuleID ||
          item.rule_id ||
          item.Rule ||
          (item.rule && item.rule.id);
        const hasBanditID = item.test_name;
        const hasContainerID = item.ID;
        if (hasTrivyID) return "trivy";
        if (hasGitleaksID) return "gitleaks";
        if (hasBanditID) return "bandit";
        if (hasContainerID) return "container";
        return "unknown";
      }

      function getSeverity(item) {
        if (item.Entropy !== undefined) {
          if (item.Entropy > 4.5) return "Critical";
          if (item.Entropy > 4) return "High";
          if (item.Entropy > 3.5) return "Medium";
          return "Low";
        }
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

      function getLine(item) {
        return (
          item.StartLine ||
          item.line_number ||
          item.Line ||
          item.Location?.StartLine ||
          item.location?.start?.line ||
          null
        );
      }

      function getFilePath(item) {
        return (
          item.file ||
          item.File ||
          item.filename ||
          item.file_path ||
          item.FilePath ||
          item.Target ||
          item.Location?.Path ||
          item.location?.file ||
          item.location?.path ||
          null
        );
      }

      const allFindings = [
        ...(globalFindings || []),
        ...(globalTrivy?.Results?.flatMap(r => r.Vulnerabilities || []) || []),
        ...(globalBandit || []),
        ...(containerData?.top_vulnerabilities || []),
      ];


      const normalizedFindings = allFindings.map((item) => ({
        ...item,
        severity: getSeverity(item),
        scanner: getScannerName(item),
      }));

      const clickedSeverityLower = (clickedSeverity || "").toString().toLowerCase();
      const clickedScannerLower = (clickedScanner || "").toString().trim().toLowerCase();


      const findingsForSeverity = normalizedFindings.filter(
        (item) =>
          item.severity.toLowerCase() === clickedSeverityLower &&
          item.scanner.toLowerCase() === clickedScannerLower
      );

      const findingsWithLines = findingsForSeverity.map((item) => ({
        ...item,
        line: getLine(item),
        file: getFilePath(item),
      }));

      rawHtml = rawHtml.replace(
        "</head>",
        `<script>
          const selectedSeverityLabel = ${JSON.stringify(clickedSeverity)};
          const occurrences = ${JSON.stringify(findingsWithLines)};
        </script></head>`
      );

      detailPanel.webview.html = rawHtml;

      detailPanel.webview.onDidReceiveMessage(
        (message) => {
          if (message.command === "openAlertBanner" && message.alertItem) {
            openAlertBanner(message.alertItem);
          }
        },
        undefined,
        context.subscriptions
      );
    }
  });
}

function getTempScanDir() {
  const workspacePath =
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || "default";
  return path.join(os.tmpdir(), "devsecode", path.basename(workspacePath));
}
function getChartImages() {
  return chartImages; 
}

module.exports = { showDashboard, getChartImages };
