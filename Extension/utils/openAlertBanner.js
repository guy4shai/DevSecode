const vscode = require("vscode");
const path = require("path");
const fs = require("fs");

let currentTrivyFindings = []; 
let currentFindings = [];      
let currentBanditFindings = [];
let currentContainerFindings = [];


function setCurrentFindings(findings) {
  currentFindings = findings;
}

function setCurrentTrivyFindings(findings) {
  currentTrivyFindings = findings;
}

function setCurrentBanditFindings(list) {
  currentBanditFindings = Array.isArray(list) ? list : [];
}

function setCurrentContainerFindings(findings) {
  currentContainerFindings = findings;
}


function openAlertBanner(alertItem) {
  const id =
    alertItem.RuleID ||
    alertItem.VulnerabilityID ||
    alertItem.test_name ||
    alertItem.ID ||
    "Unknown";
  const panelTitle = `Alert: ${id}`;

  const alertPanel = vscode.window.createWebviewPanel(
    "alertDetail",
    panelTitle,
    vscode.ViewColumn.Active,
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.file(path.join(__dirname, "..", "UI"))], // תקן את הנתיב במידת הצורך
    }
  );

  const htmlPath = path.join(__dirname, "..", "UI", "alertpage.html");
  let html = fs.readFileSync(htmlPath, "utf8");

  let reportData = [];

// רשימת קונטיינרים מאוחדת (תומך גם במבנה המשולב עם reports)
const containerList = (() => {
  const cf = currentContainerFindings;
  if (!cf) return [];
  if (Array.isArray(cf.reports)) {
    return cf.reports.flatMap((r) => [
      ...(Array.isArray(r.top_vulnerabilities) ? r.top_vulnerabilities : []),
      ...(Array.isArray(r.Results)
        ? r.Results.flatMap((res) => res.Vulnerabilities || [])
        : []),
    ]);
  }
  // תמיכה לאחור אם נשמר בלי reports
  const top = Array.isArray(cf.top_vulnerabilities) ? cf.top_vulnerabilities : [];
  const fromResults = Array.isArray(cf.Results)
    ? cf.Results.flatMap((res) => res.Vulnerabilities || [])
    : [];
  return [...top, ...fromResults];
})();

// 1) קונטיינר: כשמגיעים מה-Tree יש לנו item.ID (CVE)
if (alertItem.ID) {
  reportData = containerList;

// 2) Trivy FS / SCA: מזהים לפי VulnerabilityID
} else if (alertItem.VulnerabilityID) {
  if (Array.isArray(currentTrivyFindings)) {
    reportData = currentTrivyFindings;
  } else if (currentTrivyFindings?.Results) {
    reportData = currentTrivyFindings.Results.flatMap(
      (result) => result.Vulnerabilities || []
    );
  } else {
    reportData = [];
  }

// 3) Bandit
} else if (
  alertItem.test_name ||
  alertItem.issue_text ||
  alertItem.issue_severity
) {
  reportData = Array.isArray(currentBanditFindings) ? currentBanditFindings : [];

// 4) Gitleaks (ברירת מחדל)
} else {
  reportData = currentFindings || [];
}

  const filePath =
    alertItem.file ||
    alertItem.File ||
    alertItem.FilePath ||
    (alertItem.Location && alertItem.Location.Path) ||
    alertItem.filename ||
    alertItem.file_path ||
    "";

  const startLine =
    alertItem.line ||
    alertItem.line_number ||
    alertItem.Line ||
    alertItem.StartLine ||
    (alertItem.Location && alertItem.Location.StartLine) ||
    (alertItem.location && alertItem.location.start?.line) ||
    0;

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

  console.log("🔍 openAlertBanner alertItem:", alertItem);
  console.log("🔍 openAlertBanner reportData length:", reportData.length);
  console.log("🔍 openAlertBanner first reportData item:", reportData[0]);


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

module.exports = {
  openAlertBanner,
  setCurrentFindings,
  setCurrentTrivyFindings,
  setCurrentBanditFindings,
  setCurrentContainerFindings
};
