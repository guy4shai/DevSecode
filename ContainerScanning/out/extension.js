"use strict";
// import * as vscode from 'vscode';
// import * as path from 'path';
// import { ContainerScanner } from './containerScanner';
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
// export function activate(context: vscode.ExtensionContext) {
//   const diagnostics = vscode.languages.createDiagnosticCollection('containerScan');
//   context.subscriptions.push(diagnostics);
//   const outputChannel = vscode.window.createOutputChannel('Container Scan');
//   context.subscriptions.push(outputChannel);
//   const scanner = new ContainerScanner(context, diagnostics);
//   const disposable = vscode.commands.registerCommand(
//     'extension.scanContainer',
//     async () => {
//       const workspaceFolders = vscode.workspace.workspaceFolders;
//       if (!workspaceFolders) {
//         return vscode.window.showWarningMessage('No workspace open');
//       }
//       const dockerfileUri = vscode.Uri.joinPath(
//         workspaceFolders[0].uri,
//         'Dockerfile'
//       );
//       let doc: vscode.TextDocument;
//       try {
//         doc = await vscode.workspace.openTextDocument(dockerfileUri);
//       } catch {
//         return vscode.window.showErrorMessage(
//           'Dockerfile not found in workspace root'
//         );
//       }
//       const text = doc.getText();
//       const lines = text.split(/\r?\n/);
//       let image: string | undefined;
//       for (const line of lines) {
//         const trimmed = line.trim();
//         if (!trimmed || trimmed.startsWith('#')) continue;
//         const m = trimmed.match(/^FROM\s+(.+)$/i);
//         if (m) {
//           image = m[1].trim();
//           break;
//         }
//       }
//       if (!image) {
//         return vscode.window.showWarningMessage(
//           'No FROM instruction found in Dockerfile'
//         );
//       }
//       outputChannel.clear();
//       outputChannel.appendLine(`Starting scan for image: ${image}`);
//       vscode.window.showInformationMessage(
//         `Starting container scan for image: ${image}`
//       );
//       try {
//         const jsonPath = await scanner.scanImage(image, dockerfileUri);
//         outputChannel.appendLine(
//           `Scan complete. Results saved to ${jsonPath}`
//         );
//         vscode.window.showInformationMessage(
//           `Container scan complete. Results: ${jsonPath}`
//         );
//         outputChannel.show(true);
//       } catch (err: any) {
//         const msg =
//           err instanceof Error ? err.message : String(err);
//         outputChannel.appendLine(`Scan error: ${msg}`);
//         vscode.window.showErrorMessage(`Scan error: ${msg}`);
//         outputChannel.show(true);
//       }
//     }
//   );
//   context.subscriptions.push(disposable);
// }
// export function deactivate() {}
const vscode = require("vscode");
const fs = require("fs");
const containerScanner_1 = require("./containerScanner");
function activate(context) {
    const diagnostics = vscode.languages.createDiagnosticCollection('containerScan');
    context.subscriptions.push(diagnostics);
    const outputChannel = vscode.window.createOutputChannel('Container Scan');
    context.subscriptions.push(outputChannel);
    const scanner = new containerScanner_1.ContainerScanner(context, diagnostics, outputChannel);
    const disposable = vscode.commands.registerCommand('extension.scanContainer', () => __awaiter(this, void 0, void 0, function* () {
        const wsFolders = vscode.workspace.workspaceFolders;
        if (!wsFolders) {
            return vscode.window.showWarningMessage('No workspace open');
        }
        const dockerfileUri = vscode.Uri.joinPath(wsFolders[0].uri, 'Dockerfile');
        let doc;
        try {
            doc = yield vscode.workspace.openTextDocument(dockerfileUri);
        }
        catch (_a) {
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
            const jsonPath = yield scanner.scanImage(image, dockerfileUri);
            // Show only initial Starting scan and summary
            const startMsg = `Starting scan for image: ${image}`;
            outputChannel.clear();
            outputChannel.appendLine(startMsg);
            outputChannel.appendLine('Scan complete.');
            outputChannel.appendLine('');
            let summary = '';
            try {
                const raw = yield fs.promises.readFile(jsonPath, 'utf8');
                const parsed = JSON.parse(raw);
                summary = parsed.summary || '';
            }
            catch (_b) {
                // ignore
            }
            if (summary) {
                outputChannel.appendLine(summary);
                outputChannel.appendLine('');
            }
            outputChannel.appendLine(`For more details, results saved to ${jsonPath}`);
            vscode.window.showInformationMessage('Scan complete.');
            outputChannel.show(true);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            outputChannel.appendLine(`Scan error: ${msg}`);
            vscode.window.showErrorMessage(`Scan error: ${msg}`);
            outputChannel.show(true);
        }
    }));
    context.subscriptions.push(disposable);
}
exports.activate = activate;
function deactivate() { }
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map