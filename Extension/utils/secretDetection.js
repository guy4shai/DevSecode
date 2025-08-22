const vscode = require("vscode");
const fs = require("fs");
const path = require("path");

let diagnosticCollection;

function initSecretScanner(context, getTempScanDir, alertsProvider) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection("secretScanner");
    context.subscriptions.push(diagnosticCollection);

    context.subscriptions.push(registerSecretFixCommand());
    context.subscriptions.push(registerSecretQuickFix());

    watchGitleaksReport(context, getTempScanDir, alertsProvider);
}

function registerSecretFixCommand() {
    return vscode.commands.registerCommand(
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
}

function registerSecretQuickFix() {
    return vscode.languages.registerCodeActionsProvider("*", {
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
}

function watchGitleaksReport(context, getTempScanDir, alertsProvider) {
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

function showDiagnostics(findings) {
    console.log("🧪 Total findings received:", findings.length);
    console.log(
        "📂 Files found:",
        findings.map((f) => f.File)
    );

    const diagnosticsMap = new Map(); // key: string
    const diagnosticUriMap = new Map(); // key: string → Uri

    findings.forEach((finding) => {
        const filePath = path.resolve(finding.File); // Normalize path
        const fileKey = filePath;
        const fileUri = vscode.Uri.file(filePath);

        diagnosticUriMap.set(fileKey, fileUri);

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

        if (!diagnosticsMap.has(fileKey)) {
            diagnosticsMap.set(fileKey, []);
        }
        diagnosticsMap.get(fileKey).push(diagnostic);
    });

    diagnosticCollection.clear();
    diagnosticsMap.forEach((diags, key) => {
        const uri = diagnosticUriMap.get(key);
        console.log(
            "📂 Final diagnostics for:",
            uri.fsPath,
            "→",
            diags.length,
            "issues"
        );
        diagnosticCollection.set(uri, diags);
    });
}

module.exports = {
    initSecretScanner,
    showDiagnostics,
};
