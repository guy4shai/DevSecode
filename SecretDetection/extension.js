// File: extension.js
const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const fs = require('fs');

function activate(context) {
  let disposable = vscode.commands.registerCommand('secretScanner.runScan', async (uri) => {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      vscode.window.showErrorMessage('No workspace folder found. Please open a folder first.');
      return;
    }

    // 1. Determine which folder to scan
    let rootPath;
    if (uri && uri.fsPath) {
      // If command was invoked by right-click on a file
      rootPath = path.dirname(uri.fsPath);
    } else {
      // Otherwise, use the first workspace folder
      rootPath = workspaceFolders[0].uri.fsPath;
    }

    // 2. Locate gitleaks.toml
    const configPathProject = path.join(rootPath, 'gitleaks.toml');
    const extensionDir = context.extensionPath;
    const configPathFallback = path.join(extensionDir, 'gitleaks.toml');
    const configToUse = fs.existsSync(configPathProject)
      ? configPathProject
      : fs.existsSync(configPathFallback)
        ? configPathFallback
        : null;

    // // 3. Define a temporary JSON report path
    // const reportPath = path.join(rootPath, 'gitleaks_report.json');

    // // 4. Build the Gitleaks command
    // //    You can add --no-color --no-banner if your version supports it
    // const command = configToUse
    //   ? `gitleaks detect --config="${configToUse}" --no-git --source="${rootPath}" --redact --report-format=json --report-path="${reportPath}"`
    //   : `gitleaks detect --no-git --source="${rootPath}" --redact --report-format=json --report-path="${reportPath}"`;
    
    // 3. Define the JSON report path under UI/json_output
    const workspaceRoot = workspaceFolders[0].uri.fsPath;
    const outputDir = path.join(workspaceRoot, 'UI', 'json_output');
    // Ensure the folder exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    // Report will be saved to UI/json_output/gitleaks_report.json
    const reportPath = path.join(outputDir, 'gitleaks_report.json');
    // Show the user what we're doing (but don't actually run in that terminal)
    const debugTerminal = vscode.window.createTerminal("Secret Scan Debug");
    debugTerminal.show();
    debugTerminal.sendText(`echo "Running Secret Scan on: ${rootPath}"`);
    debugTerminal.sendText(`echo "Command: ${command}"`);

    // 5. Make sure gitleaks is installed
    cp.exec('gitleaks version', (versionErr) => {
      if (versionErr) {
        vscode.window.showErrorMessage(
          `Gitleaks is not installed or not available in PATH.\nPlease install it from https://github.com/gitleaks/gitleaks/releases`
        );
        return;
      }

      // 6. Show a loading animation in VSCode
      vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Running Secret Scan...",
        cancellable: false
      }, () => {
        return new Promise((resolve) => {
          // 7. Actually run the command
          cp.exec(command, { maxBuffer: 1024 * 1000 }, (err, stdout, stderr) => {
            // 8. Check if the JSON report file was created
            if (!fs.existsSync(reportPath)) {
              vscode.window.showInformationMessage('No JSON report created. Possibly no leaks or an error occurred.');
              debugTerminal.sendText(`echo "No gitleaks_report.json found"`);
              return resolve();
            }

            const rawContent = fs.readFileSync(reportPath, 'utf8').trim();
            if (!rawContent) {
              vscode.window.showInformationMessage('No secrets found. The report file is empty.');
              vscode.window.showInformationMessage('Secret Scan complete. Check Problems panel for results.');
              debugTerminal.sendText(`echo "Empty gitleaks_report.json"`);
              // Optionally remove the file if desired
              // fs.unlinkSync(reportPath);
              return resolve();
            }

            // 9. Attempt to parse JSON
            let findings;
            try {
              findings = JSON.parse(rawContent);
            } catch (parseErr) {
              // JSON was invalid
              vscode.window.showWarningMessage('Scan completed, but JSON parse failed. See terminal for raw output.');
              const term = vscode.window.createTerminal("Secret Scanner Raw Output");
              term.show();
              term.sendText(rawContent);
              // fs.unlinkSync(reportPath);
              return resolve();
            }

            // 10. If there are no findings in the report - show a relevant message
            if (!Array.isArray(findings) || findings.length === 0) {
              vscode.window.showInformationMessage('No secrets found in scan.');
              debugTerminal.sendText(`echo "No secrets found in JSON"`);
            } else {
              // 11. Print findings to the terminal (without logs)
              let summary = 'Found secrets:\n';
              findings.forEach((item) => {
                summary += `File: ${item.File}\nLine: ${item.StartLine}\nRule: ${item.RuleID}\nDesc: ${item.Description}\n\n`;
              });
              debugTerminal.sendText(`echo "${summary}"`);

              // 12. Create diagnostics for the Problems Panel
              showDiagnostics(findings);
            }

            vscode.window.showInformationMessage('Secret Scan complete. Check Problems panel for results.');
            // fs.unlinkSync(reportPath);
            resolve();
          });
        });
      });
    });
  });

  context.subscriptions.push(disposable);
}

function showDiagnostics(findings) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('secretScanner');
  const diagnosticsMap = new Map();

  findings.forEach(finding => {
    const fileUri = vscode.Uri.file(finding.File);
    const line = finding.StartLine ? finding.StartLine - 1 : 0;
    const range = new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, 80));

    const tooltip = [
      `Rule: ${finding.RuleID}`,
      `Description: ${finding.Description || 'Potential secret detected.'}`,
      finding.Secret ? `Secret: ${finding.Secret}` : '',
      finding.redacted ? '(Secret redacted)' : ''
    ].join('\n');

    const message = `${finding.RuleID}: ${finding.Description || 'Potential secret detected.'}`;
    const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'Secret Scanner';
    diagnostic.code = finding.RuleID;
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(fileUri, tooltip)
    ];

    if (!diagnosticsMap.has(fileUri)) {
      diagnosticsMap.set(fileUri, []);
    }
    diagnosticsMap.get(fileUri).push(diagnostic);
  });

  // clear old diagnostics
  diagnosticCollection.clear();
  // show new ones
  diagnosticsMap.forEach((diags, uri) => {
    diagnosticCollection.set(uri, diags);
  });
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};
