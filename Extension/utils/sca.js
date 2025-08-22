const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const { getFixedVersionFromOSV } = require("./osvApiHelper");

let diagnosticCollection;
let scaDiagnostics = vscode.languages.createDiagnosticCollection("sca");

function initSCA(context, getTempScanDir, alertsProvider) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection("sca");
    context.subscriptions.push(diagnosticCollection);

    context.subscriptions.push(registerScaQuickFix());
}

function showScaDiagnostics(trivyReportPath, requirementsPath) {
  if (!fs.existsSync(trivyReportPath)) {
    console.warn("Trivy report not found at:", trivyReportPath);
    return;
  }

  const raw = fs.readFileSync(trivyReportPath, "utf-8");
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    console.warn("Failed to parse Trivy report:", e);
    return;
  }

  const diagnosticsMap = new Map();

  // הסתכלי על מבנה הממצאים, התאמה לסריקות מסוג SCA
  const findings = data?.Results?.flatMap((r) => r.Vulnerabilities || []) || [];

  for (const vuln of findings) {
    const filePath = vscode.Uri.file(requirementsPath);
    const lineNumber = vuln.line_number ?? 0; // ודאי ששדה כזה קיים אצלך
    const range = new vscode.Range(lineNumber, 0, lineNumber, 100);
    const severity =
      vuln.Severity === "CRITICAL"
        ? vscode.DiagnosticSeverity.Error
        : vuln.Severity === "HIGH"
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

    const message = `[${vuln.Severity}] ${vuln.VulnerabilityID}: ${vuln.Title}`;

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.code = vuln.VulnerabilityID;
    diagnostic.source = "Trivy";

    if (!diagnosticsMap.has(filePath)) {
      diagnosticsMap.set(filePath, []);
    }

    diagnosticsMap.get(filePath).push(diagnostic);
  }

  scaDiagnostics.clear();
  for (const [file, diags] of diagnosticsMap) {
    scaDiagnostics.set(file, diags);
  }
}

function registerScaQuickFix() {
    return vscode.languages.registerCodeActionsProvider("*", {
        async provideCodeActions(document, range, context) {
            const actions = [];

            for (const diagnostic of context.diagnostics) {
                if (diagnostic.source === "SCA" && diagnostic.osv) {
                    const { package, version } = diagnostic.osv;
                    const fixedVersion = await getFixedVersionFromOSV(package, version);

                    if (fixedVersion) {
                        const fix = new vscode.CodeAction(
                            `⬆️ Upgrade to ${fixedVersion}`,
                            vscode.CodeActionKind.QuickFix
                        );

                        fix.diagnostics = [diagnostic];
                        fix.edit = new vscode.WorkspaceEdit();

                        const originalLine = document.lineAt(range.start.line).text;
                        const updatedLine = originalLine.replace(
                            `${package}==${version}`,
                            `${package}==${fixedVersion}`
                        );

                        fix.edit.replace(
                            document.uri,
                            document.lineAt(range.start.line).range,
                            updatedLine
                        );

                        fix.command = {
                            title: "Warn about checking import usage",
                            command: "vscode.showInformationMessage",
                            arguments: [
                                `⚠️ Make sure to check if other parts of your code need updating after upgrading ${package}.`,
                            ],
                        };

                        actions.push(fix);
                    }
                }
            }

            return actions;
        },
    });
}

function attachFilePathToTrivyFindings(trivyReportPath) {
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

// function registerScaInlineFixes(context) {
//     // 🎯 רישום hover על requirements.txt
//     context.subscriptions.push(
//         vscode.languages.registerHoverProvider(
//             { pattern: "**/requirements.txt" },
//             {
//                 async provideHover(document, position) {
//                     const lineText = document.lineAt(position.line).text;

//                     const match = lineText.match(/^([a-zA-Z0-9_\-]+)==([\d\.]+)$/);
//                     if (!match) return;

//                     const packageName = match[1];
//                     const version = match[2];

//                     try {
//                         const fixes = await getFixedVersionFromOSV(
//                             packageName,
//                             version
//                         );

//                         const cleanFixes = Array.from(
//                             new Set(fixes.filter((v) => /^\d+\.\d+(\.\d+)?$/.test(v)))
//                         );

//                         if (cleanFixes.length > 0) {
//                             return new vscode.Hover(
//                                 `⚠️ **${packageName}==${version}** is vulnerable.\n\n💡 Recommended versions:\n- ${cleanFixes.join(
//                                     "\n- "
//                                 )}`
//                             );
//                         }
//                     } catch (err) {
//                         console.error("❌ Hover error:", err);
//                     }

//                     return; // אין תיקונים => לא מציגים כלום
//                 },
//             }
//         )
//     );

//     context.subscriptions.push(
//         vscode.languages.registerCodeActionsProvider(
//             { pattern: "**/requirements.txt" },
//             {
//                 async provideCodeActions(document, range, context) {
//                     const actions = [];

//                     const lineText = document.lineAt(range.start.line).text;
//                     const match = lineText.match(/^([a-zA-Z0-9_\-]+)==([\d\.]+)$/);
//                     if (!match) return;

//                     const packageName = match[1];
//                     const version = match[2];

//                     const fixes = await getFixedVersionFromOSV(packageName, version);
//                     if (!fixes || fixes.length === 0) return;

//                     const cleanFixes = Array.from(
//                         new Set(fixes.filter((v) => /^\d+\.\d+(\.\d+)?$/.test(v)))
//                     );

//                     if (cleanFixes.length === 0) return;

//                     const diagnostic = new vscode.Diagnostic(
//                         range,
//                         `❌ Vulnerable package: ${packageName}==${version}`,
//                         vscode.DiagnosticSeverity.Error
//                     );
//                     diagnostic.source = "SCA";

//                     // בדיקה אם כבר קיים, כמו קודם:
//                     const existing = scaDiagnostics.get(document.uri) || [];
//                     const alreadyExists = existing.some(
//                         (d) =>
//                             d.range.start.line === diagnostic.range.start.line &&
//                             d.message === diagnostic.message
//                     );
//                     if (!alreadyExists) {
//                         const updated = [...existing, diagnostic];
//                         scaDiagnostics.set(document.uri, updated);
//                     }

//                     const fix = new vscode.CodeAction(
//                         `🛠 Update ${packageName} to a safer version`,
//                         vscode.CodeActionKind.QuickFix
//                     );
//                     fix.command = {
//                         title: "Choose safe version",
//                         command: "devsecode.updatePackageVersion",
//                         arguments: [document, range, packageName, version, cleanFixes],
//                     };

//                     return [fix];
//                 },
//             },
//             {
//                 providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
//             }
//         )
//     );

//     context.subscriptions.push(
//         vscode.commands.registerCommand(
//             "devsecode.updatePackageVersion",
//             async (document, range, packageName, currentVersion, fixes) => {
//                 const version = await vscode.window.showQuickPick(fixes, {
//                     placeHolder: `Choose a secure version for ${packageName}`,
//                 });

//                 if (!version) return;

//                 const newLine = `${packageName}==${version}`;
//                 const edit = new vscode.WorkspaceEdit();
//                 const fullRange = document.lineAt(range.start.line).range;

//                 await edit.replace(document.uri, fullRange, newLine);
//                 await vscode.workspace.applyEdit(edit);

//                 vscode.window.showInformationMessage(
//                     `✅ Updated ${packageName} from ${currentVersion} to ${version}`
//                 );

//                 vscode.window.showWarningMessage(
//                     `⚠️ Make sure to review any code that uses '${packageName}' (e.g., 'import ${packageName}') to ensure compatibility with version ${version}.`
//                 );

//                 scaDiagnostics.delete(document.uri);
//             }
//         )
//     );
// }

function registerScaInlineFixes(context) {
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

                    // ✅ יוצרים הערת שגיאה עם מקור "SCA"
                    const diagnostic = new vscode.Diagnostic(
                        range,
                        `❌ Vulnerable package: ${packageName}==${version}\n💡 Recommended versions:\n- ${cleanFixes.join("\n- ")}`,
                        vscode.DiagnosticSeverity.Error
                    );
                    diagnostic.source = "SCA";

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

                    // 🛠 פעולה לתיקון מהיר
                    const fix = new vscode.CodeAction(
                        `⬆️ Upgrade ${packageName} to a safer version`,
                        vscode.CodeActionKind.QuickFix
                    );
                    fix.diagnostics = [diagnostic];
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

    // 🟢 פעולה שמריצה את התיקון בפועל
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
                    `⚠️ Make sure to review any code that uses '${packageName}' (e.g., 'import ${packageName}')`
                );

                scaDiagnostics.delete(document.uri);
            }
        )
    );
}

module.exports = {
  initSCA,
  showScaDiagnostics,
  attachFilePathToTrivyFindings,
  attachLinesToTrivy,
  registerScaInlineFixes,
};
