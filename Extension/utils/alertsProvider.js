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
    const containerFindings = (() => {
      const cf = currentContainerFindings;
      if (!cf) return [];
      if (Array.isArray(cf.reports)) {
        return cf.reports.flatMap((r) =>
          Array.isArray(r.top_vulnerabilities) ? r.top_vulnerabilities : []
        );
      }
      return Array.isArray(cf.top_vulnerabilities) ? cf.top_vulnerabilities : [];
    })();

    const combinedFindings = [
      ...(currentFindings || []),
      ...(currentTrivyFindings?.Results?.flatMap(
        (r) => r.Vulnerabilities || []
      ) || []),
      ...(currentBanditFindings || []),
      ...(containerFindings || []),
    ];


    console.log("🧪 Bandit Findings in TreeView:", currentBanditFindings);
    console.log("🧩 All Combined Findings:", combinedFindings);

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

    function getSeverity(item) {
      // Gitleaks משתמש ב-Entropy
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

    function getAlertId(item) {
      return item.RuleID || item.VulnerabilityID || item.test_name || item.ID || "Unknown";
    }

    function getLine(item) {
      return (
        item.StartLine ||
        item.Location?.StartLine ||
        item.Line ||
        item.line_number ||
        "none"
      );
    }
    const sortedFindings = combinedFindings
      .map((item, idx) => {
        const severity = getSeverity(item);
        const alertId = getAlertId(item);
        const line = getLine(item);

        console.log("🧠 Mapped Alert", idx, { alertId, line, severity, item });

        item.severity = severity;
        item.alertId = alertId;
        item.line = line;

        return item; 
      })

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
        const severity = item.severity || item.Severity || item.issue_severity;
        const filePath =
          item.File ||
          item.Path ||
          item.filename ||
          item.file_path ||
          item.Location?.Path ||
          "";
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
  AlertsProvider,
  setCurrentFindings,
  setCurrentTrivyFindings,
  setCurrentContainerFindings,
  setCurrentBanditFindings,
};