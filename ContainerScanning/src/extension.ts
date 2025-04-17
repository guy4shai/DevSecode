import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { ContainerScanner } from './containerScanner';

export function activate(context: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection('containerScan');
  context.subscriptions.push(diagnostics);

  const outputChannel = vscode.window.createOutputChannel('Container Scan');
  context.subscriptions.push(outputChannel);

  const scanner = new ContainerScanner(context, diagnostics, outputChannel);

  const disposable = vscode.commands.registerCommand('extension.scanContainer', async () => {
    const wsFolders = vscode.workspace.workspaceFolders;
    if (!wsFolders) {
      return vscode.window.showWarningMessage('No workspace open');
    }

    const dockerfileUri = vscode.Uri.joinPath(wsFolders[0].uri, 'Dockerfile');
    let doc: vscode.TextDocument;
    try {
      doc = await vscode.workspace.openTextDocument(dockerfileUri);
    } catch {
      return vscode.window.showErrorMessage('Dockerfile not found in workspace root');
    }

    const lines = doc.getText().split(/\r?\n/);
    const fromLine = lines.find(line => /^FROM\s+/i.test(line));
    if (!fromLine) {
      return vscode.window.showWarningMessage('No FROM instruction found');
    }
    const image = fromLine.replace(/^FROM\s+/i, '').trim();

    outputChannel.clear();
    outputChannel.appendLine(`Starting scan for image: ${image}`);
    vscode.window.showInformationMessage(`Starting container scan for image: ${image}`);

    try {
      const jsonPath = await scanner.scanImage(image, dockerfileUri);

      // Show only initial Starting scan and summary
      const startMsg = `Starting scan for image: ${image}`;
      outputChannel.clear();
      outputChannel.appendLine(startMsg);
      outputChannel.appendLine('Scan complete.');
      outputChannel.appendLine('');

      let summary = '';
      try {
        const raw = await fs.promises.readFile(jsonPath, 'utf8');
        const parsed = JSON.parse(raw);
        summary = parsed.summary || '';
      } catch {
        // ignore
      }
      if (summary) {
        outputChannel.appendLine(summary);
        outputChannel.appendLine('');
      }
      outputChannel.appendLine(`For more details, results saved to ${jsonPath}`);
      vscode.window.showInformationMessage('Scan complete.');
      outputChannel.show(true);
    } catch (err: any) {
      const msg = err instanceof Error ? err.message : String(err);
      outputChannel.appendLine(`Scan error: ${msg}`);
      vscode.window.showErrorMessage(`Scan error: ${msg}`);
      outputChannel.show(true);
    }
  });

  context.subscriptions.push(disposable);
}

export function deactivate() {}