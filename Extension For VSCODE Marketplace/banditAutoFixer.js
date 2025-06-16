const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

// ⬇️ Map של RuleID → קובץ פיקסר
const fixers = {
  B101: require("./fixers/B101"),
  B324: require("./fixers/B324"),
  B102: require("./fixers/B102"),
  B103: require("./fixers/B103"),
  B104: require("./fixers/B104"),
  B105: require("./fixers/B105"),
  B106: require("./fixers/B106"),
  B107: require("./fixers/B107"),
  B108: require("./fixers/B108"),
  B109: require("./fixers/B109"),
  B112: require("./fixers/B112"),
  B113: require("./fixers/B113"),
  B201: require("./fixers/B201"),
  B202: require("./fixers/B202"),
  B501: require("./fixers/B501"),
  B502: require("./fixers/B502"),
  B503: require("./fixers/B503"),
  B505: require("./fixers/B505"),
  B506: require("./fixers/B506"),
  B508: require("./fixers/B508"),
  B509: require("./fixers/B509"),
  B601: require("./fixers/B601"),
  B602: require("./fixers/B602"),
  B603: require("./fixers/B603"),
  B605: require("./fixers/B605"),
  B606: require("./fixers/B606"),
  B607: require("./fixers/B607"),
  B608: require("./fixers/B608"),
  B609: require("./fixers/B609"),
  B610: require("./fixers/B610"),
  B611: require("./fixers/B611"),
  B612: require("./fixers/B612"),
  B613: require("./fixers/B613"),
  B614: require("./fixers/B614"),
  B701: require("./fixers/B701"),
  B703: require("./fixers/B703"),
  B704: require("./fixers/B704"),
};

let banditDiagnosticCollection;

/**
 * ✅ רישום Quick Fixes לפי RuleID
 */
function registerBanditAutoFixes(context) {
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider("*", {
      provideCodeActions(document, range, context) {
        const actions = [];

        for (const diagnostic of context.diagnostics) {
          const match = diagnostic.message.match(/Rule:\s*(B\d{3})/);
          const ruleId = match?.[1];
          const fixer = fixers[ruleId];

          if (ruleId && fixer) {
            const fix = new vscode.CodeAction(
              `🛠 תקן אוטומטית (${ruleId})`,
              vscode.CodeActionKind.QuickFix
            );
            fix.command = {
              title: "Run Bandit Auto Fix",
              command: "bandit.autoFix",
              arguments: [document, diagnostic.range, ruleId],
            };
            fix.diagnostics = [diagnostic];
            actions.push(fix);
          }
        }

        return actions;
      },
    }, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("bandit.autoFix", async (document, range, ruleId) => {
      const fixer = fixers[ruleId];
      if (!fixer) return;

      const edit = await fixer(document, range);
      await vscode.workspace.applyEdit(edit);
      // הסרת הסימון לאחר תיקון
      const uri = document.uri;
      const diagnostics = banditDiagnosticCollection.get(uri) || [];
      const newDiagnostics = diagnostics.filter(d => !d.range.isEqual(range));
      banditDiagnosticCollection.set(uri, newDiagnostics);
      vscode.window.showInformationMessage(`✅ ${ruleId} תוקן בהצלחה.`);
    })
  );
}

/**
 * ✅ הצגת סימונים מהדוח של Bandit
 */
function showBanditDiagnostics(context, getTempScanDir) {
  const scanPath = path.join(getTempScanDir(), "bandit_report.json");
  if (!fs.existsSync(scanPath)) {
    console.warn("❌ bandit_report.json not found.");
    return;
  }

  let results = [];
  try {
    const raw = fs.readFileSync(scanPath, "utf8");
    results = JSON.parse(raw).results || [];
  } catch (e) {
    console.warn("❌ Failed to parse Bandit report.");
    return;
  }

  if (!banditDiagnosticCollection) {
    banditDiagnosticCollection = vscode.languages.createDiagnosticCollection("bandit");
    context.subscriptions.push(banditDiagnosticCollection);
  }

  banditDiagnosticCollection.clear();

  const diagnosticsMap = new Map();

  results.forEach((finding) => {
    const fileUri = vscode.Uri.file(finding.filename);
    const line = finding.line_number > 0 ? finding.line_number - 1 : 0;

    const range = new vscode.Range(
      new vscode.Position(line, 0),
      new vscode.Position(line, 100)
    );

    const ruleId = finding.test_id;
    const message = `🚨 Rule: ${ruleId}\n${finding.issue_text}`;
    const severity = getSeverityLevel(finding.issue_severity);

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = "Bandit";
    
    try {
      const fileLines = fs.readFileSync(finding.filename, "utf8").split("\n");
      diagnostic.originalText = fileLines[line] || "";
    } catch (e) {
      diagnostic.originalText = "";
    }
    
    if (!diagnosticsMap.has(fileUri.fsPath)) {
      diagnosticsMap.set(fileUri.fsPath, []);
    }
    diagnosticsMap.get(fileUri.fsPath).push(diagnostic);
  });

  diagnosticsMap.forEach((diags, filePath) => {
    const uri = vscode.Uri.file(filePath);
    banditDiagnosticCollection.set(uri, diags);
  });
}

/**
 * 🎨 המרת חומרה לטווח צבעים
 */
function getSeverityLevel(sev) {
  switch (sev?.toLowerCase()) {
    case "low":
      return vscode.DiagnosticSeverity.Information;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "high":
    case "critical":
      return vscode.DiagnosticSeverity.Error;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

module.exports = {
  showBanditDiagnostics,
  registerBanditAutoFixes,
};
