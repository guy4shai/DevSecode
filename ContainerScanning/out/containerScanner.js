"use strict";
// import * as vscode from 'vscode';
// import { spawn } from 'child_process';
// import * as fs from 'fs';
// import * as path from 'path';
// import * as os from 'os';
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
exports.ContainerScanner = void 0;
// interface TrivyVulnerability {
//   VulnerabilityID: string;
//   PkgName: string;
//   InstalledVersion: string;
//   FixedVersion: string;
//   Severity: string;
//   PrimaryURL?: string;
//   References?: string[];
// }
// interface TrivyResult {
//   Target: string;
//   Vulnerabilities?: TrivyVulnerability[];
// }
// interface TrivyScanResult {
//   SchemaVersion: string;
//   ArtifactName: string;
//   Results: TrivyResult[];
// }
// export class ContainerScanner {
//   private cacheDir: string;
//   constructor(
//     private context: vscode.ExtensionContext,
//     private diagnostics: vscode.DiagnosticCollection,
//     private outputChannel?: vscode.OutputChannel
//   ) {
//     this.cacheDir = path.join(context.globalStorageUri.fsPath, 'trivy-db-cache');
//     fs.mkdirSync(this.cacheDir, { recursive: true });
//   }
//   private findFromLine(doc: vscode.TextDocument, image: string): number | undefined {
//     for (let i = 0; i < doc.lineCount; i++) if (doc.lineAt(i).text.includes(image) && doc.lineAt(i).text.startsWith('FROM')) return i;
//   }
//   private mapSeverity(sev: string): vscode.DiagnosticSeverity {
//     return sev === 'CRITICAL' || sev === 'HIGH' ? vscode.DiagnosticSeverity.Error : sev === 'MEDIUM' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information;
//   }
//   private publishDiagnostics(result: TrivyScanResult, dockerfileUri: vscode.Uri) {
//     const diags: vscode.Diagnostic[] = [];
//     const doc = vscode.workspace.textDocuments.find(d => d.uri.fsPath === dockerfileUri.fsPath);
//     const fromLine = doc ? this.findFromLine(doc, result.ArtifactName) ?? 0 : 0;
//     for (const res of result.Results) {
//       if (!res.Vulnerabilities) continue;
//       for (const v of res.Vulnerabilities) {
//         const sev = this.mapSeverity(v.Severity);
//         const msg = `${v.PkgName}@${v.InstalledVersion} (${v.Severity}) → ${v.VulnerabilityID}\nRecommendation: >=${v.FixedVersion}`;
//         const range = doc ? new vscode.Range(fromLine, 0, fromLine, doc.lineAt(fromLine).text.length) : new vscode.Range(0,0,0,1);
//         diags.push(new vscode.Diagnostic(range, msg, sev));
//       }
//     }
//     this.diagnostics.set(dockerfileUri, diags);
//   }
//   public async ensureDb(): Promise<void> {
//     return new Promise((resolve) => {
//       this.outputChannel?.appendLine('Updating Trivy DB...');
//       const proc = spawn('trivy', ['db', 'update', '--cache-dir', this.cacheDir], { shell: true });
//       proc.on('close', code => {
//         if (code === 0) this.outputChannel?.appendLine('DB update OK');
//         else this.outputChannel?.appendLine(`DB update failed (${code}), using cache`);
//         resolve();
//       });
//     });
//   }
// public async scanImage(image: string, dockerfileUri: vscode.Uri): Promise<string> {
//   await this.ensureDb();
//   // Dynamically determine output directory: folder of Dockerfile or cwd
//   const outputDir = path.dirname(dockerfileUri.fsPath) || process.cwd();
//   const outputName = 'ContainerScanner_outputJson.json';
//   const outputPath = path.join(outputDir, outputName);
//   return new Promise((resolve, reject) => {
//     this.outputChannel?.appendLine(`Scanning image: ${image}`);
//     const proc = spawn('trivy', ['image', '--format', 'json', '--cache-dir', this.cacheDir, '--output', outputPath, image], { shell: true });
//     proc.on('close', async code => {
//       this.outputChannel?.appendLine(`Scan exit code: ${code}`);
//       if (code !== 0 && code !== 1) return reject(new Error(`Scan failed (${code})`));
//       try {
//         const raw = await fs.promises.readFile(outputPath, 'utf8');
//         const result: TrivyScanResult = JSON.parse(raw);
//         // Remove References arrays from vulnerabilities
//   for (const resItem of result.Results) {
//   if (!resItem.Vulnerabilities) continue;
//   for (const vuln of resItem.Vulnerabilities) {
//     delete vuln.References;
//   }
//   }
//   // Build summary
//   let total = 0, critical = 0, high = 0, medium = 0, low = 0;
//   for (const res of result.Results) {
//   if (!res.Vulnerabilities) continue;
//   for (const v of res.Vulnerabilities) {
//     total++;
//     switch (v.Severity) {
//       case 'CRITICAL': critical++; break;
//       case 'HIGH': high++; break;
//       case 'MEDIUM': medium++; break;
//       case 'LOW': low++; break;
//     }
//   }
//   }
//   const summary = `Summary: Found ${total} vulnerabilities (CRITICAL: ${critical}, HIGH: ${high}, MEDIUM: ${medium}, LOW: ${low}).`;
//   // Prepend summary to JSON output
//   const enhanced = { summary, ...result };
//         await fs.promises.writeFile(outputPath, JSON.stringify(enhanced, null, 2));
//         // Print summary to output channel
//         this.outputChannel?.appendLine(summary);
//         this.publishDiagnostics(result, dockerfileUri);
//         this.outputChannel?.appendLine(`Results saved to ${outputPath}`);
//         resolve(outputPath);
//       } catch (e: any) {
//         reject(e);
//       }
//     });
//   });
// }
// }
// import * as vscode from 'vscode';
// import { spawn } from 'child_process';
// import * as fs from 'fs';
// import * as path from 'path';
// import * as os from 'os';
// interface TrivyVulnerability {
//   VulnerabilityID: string;
//   PkgName: string;
//   InstalledVersion: string;
//   FixedVersion: string;
//   Severity: string;
//   PrimaryURL?: string;
// }
// interface TrivyResult { Target: string; Vulnerabilities?: TrivyVulnerability[]; }
// interface TrivyScanResult { ArtifactName: string; Results: TrivyResult[]; }
// export class ContainerScanner {
//   private cacheDir: string;
//   constructor(
//     private context: vscode.ExtensionContext,
//     private diagnostics: vscode.DiagnosticCollection,
//     private output: vscode.OutputChannel
//   ) {
//     this.cacheDir = path.join(context.globalStorageUri.fsPath, 'trivy-db');
//     fs.mkdirSync(this.cacheDir, { recursive: true });
//   }
//   private async ensureDb(): Promise<void> {
//     this.output.appendLine('Updating Trivy DB...');
//     return new Promise(res => {
//       const proc = spawn('trivy', ['db', 'update', '--cache-dir', this.cacheDir], { shell: true });
//       proc.on('close', () => res());
//     });
//   }
//   public async scanImage(image: string, dockerfileUri: vscode.Uri): Promise<string> {
//     await this.ensureDb();
//     const dir = path.dirname(dockerfileUri.fsPath) || process.cwd();
//     const file = 'ContainerScanner_outputJson.json';
//     const outPath = path.join(dir, file);
//     this.output.appendLine(`Scanning image: ${image}`);
//     return new Promise((resolve, reject) => {
//       const proc = spawn(
//         'trivy', ['image', '--format', 'json', '--cache-dir', this.cacheDir, '--output', outPath, image],
//         { shell: true }
//       );
//       proc.on('error', err => reject(err));
//       proc.on('close', async code => {
//         if (code !== 0 && code !== 1) return reject(new Error(`Scan failed (${code})`));
//         try {
//           const raw = await fs.promises.readFile(outPath, 'utf8');
//           const parsed: TrivyScanResult = JSON.parse(raw);
//           // minimal JSON structure
//           const allVulns = parsed.Results.reduce<TrivyVulnerability[]>((acc, r) => acc.concat(r.Vulnerabilities||[]), []);
//           const vulns = allVulns.map(v => ({
//             id: v.VulnerabilityID,
//             package: v.PkgName,
//             current: v.InstalledVersion,
//             fixed: v.FixedVersion,
//             severity: v.Severity,
//             url: v.PrimaryURL||''
//           }));
//           const summary = `Summary: Found ${vulns.length} vulnerabilities (` +
//             `CRITICAL: ${vulns.filter(v=>v.severity==='CRITICAL').length}, ` +
//             `HIGH: ${vulns.filter(v=>v.severity==='HIGH').length}, ` +
//             `MEDIUM: ${vulns.filter(v=>v.severity==='MEDIUM').length}, ` +
//             `LOW: ${vulns.filter(v=>v.severity==='LOW').length}).`;
//           const minimal = { summary, artifact: parsed.ArtifactName, vulnerabilities: vulns };
//           await fs.promises.writeFile(outPath, JSON.stringify(minimal, null, 2));
//           this.publishDiagnostics(parsed, dockerfileUri);
//           this.output.appendLine(`Results saved to ${outPath}`);
//           resolve(outPath);
//         } catch (e) {
//           reject(e);
//         }
//       });
//     });
//   }
//   private publishDiagnostics(res: TrivyScanResult, uri: vscode.Uri) {
//     const diags: vscode.Diagnostic[] = [];
//     const doc = vscode.workspace.textDocuments.find(d=>d.uri.fsPath===uri.fsPath);
//     const line = doc?.getText().split(/\r?\n/).findIndex(l=>/^FROM\s+/.test(l))||0;
//     res.Results.forEach(r=>r.Vulnerabilities?.forEach(v=>{
//       const sev = v.Severity==='CRITICAL'||v.Severity==='HIGH'
//         ? vscode.DiagnosticSeverity.Error
//         : v.Severity==='MEDIUM'
//           ? vscode.DiagnosticSeverity.Warning
//           : vscode.DiagnosticSeverity.Information;
//       const msg = `${v.PkgName}@${v.InstalledVersion}→${v.VulnerabilityID}(${v.Severity})`;
//       diags.push(new vscode.Diagnostic(new vscode.Range(line,0,line,0),msg,sev));
//     }));
//     this.diagnostics.set(uri, diags);
//   }
// }
const vscode = require("vscode");
const child_process_1 = require("child_process");
const fs = require("fs");
const path = require("path");
class ContainerScanner {
    constructor(context, diagnostics, output) {
        this.context = context;
        this.diagnostics = diagnostics;
        this.output = output;
        this.cacheDir = path.join(context.globalStorageUri.fsPath, 'trivy-db');
        fs.mkdirSync(this.cacheDir, { recursive: true });
    }
    ensureDb() {
        return __awaiter(this, void 0, void 0, function* () {
            this.output.appendLine('Updating Trivy DB...');
            return new Promise(res => {
                const proc = (0, child_process_1.spawn)('trivy', ['db', 'update', '--cache-dir', this.cacheDir], { shell: true });
                proc.on('close', () => res());
            });
        });
    }
    scanImage(image, dockerfileUri) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.ensureDb();
            const dir = path.dirname(dockerfileUri.fsPath) || process.cwd();
            const file = 'ContainerScanner_outputJson.json';
            const outPath = path.join(dir, file);
            this.output.appendLine(`Scanning image: ${image}`);
            return new Promise((resolve, reject) => {
                const proc = (0, child_process_1.spawn)('trivy', ['image', '--format', 'json', '--cache-dir', this.cacheDir, '--output', outPath, image], { shell: true });
                proc.on('error', err => reject(err));
                proc.on('close', (code) => __awaiter(this, void 0, void 0, function* () {
                    if (code !== 0 && code !== 1)
                        return reject(new Error(`Scan failed (${code})`));
                    try {
                        const raw = yield fs.promises.readFile(outPath, 'utf8');
                        const parsed = JSON.parse(raw);
                        // minimal JSON structure
                        const allVulns = parsed.Results.reduce((acc, r) => acc.concat(r.Vulnerabilities || []), []);
                        const vulns = allVulns.map(v => ({
                            id: v.VulnerabilityID,
                            title: v.Title,
                            description: v.Description,
                            package: v.PkgName,
                            current: v.InstalledVersion,
                            fixed: v.FixedVersion,
                            severity: v.Severity,
                            url: v.PrimaryURL || ''
                        }));
                        const summary = `Summary: Found ${vulns.length} vulnerabilities (` +
                            `CRITICAL: ${vulns.filter(v => v.severity === 'CRITICAL').length}, ` +
                            `HIGH: ${vulns.filter(v => v.severity === 'HIGH').length}, ` +
                            `MEDIUM: ${vulns.filter(v => v.severity === 'MEDIUM').length}, ` +
                            `LOW: ${vulns.filter(v => v.severity === 'LOW').length}).`;
                        const minimal = { summary, artifact: parsed.ArtifactName, vulnerabilities: vulns };
                        yield fs.promises.writeFile(outPath, JSON.stringify(minimal, null, 2));
                        this.publishDiagnostics(parsed, dockerfileUri);
                        this.output.appendLine(`Results saved to ${outPath}`);
                        resolve(outPath);
                    }
                    catch (e) {
                        reject(e);
                    }
                }));
            });
        });
    }
    publishDiagnostics(res, uri) {
        const diags = [];
        const doc = vscode.workspace.textDocuments.find(d => d.uri.fsPath === uri.fsPath);
        const line = (doc === null || doc === void 0 ? void 0 : doc.getText().split(/\r?\n/).findIndex(l => /^FROM\s+/.test(l))) || 0;
        res.Results.forEach(r => {
            var _a;
            return (_a = r.Vulnerabilities) === null || _a === void 0 ? void 0 : _a.forEach(v => {
                const sev = v.Severity === 'CRITICAL' || v.Severity === 'HIGH'
                    ? vscode.DiagnosticSeverity.Error
                    : v.Severity === 'MEDIUM'
                        ? vscode.DiagnosticSeverity.Warning
                        : vscode.DiagnosticSeverity.Information;
                const msg = `${v.PkgName}@${v.InstalledVersion}→${v.VulnerabilityID}(${v.Severity})`;
                diags.push(new vscode.Diagnostic(new vscode.Range(line, 0, line, 0), msg, sev));
            });
        });
        this.diagnostics.set(uri, diags);
    }
}
exports.ContainerScanner = ContainerScanner;
//# sourceMappingURL=containerScanner.js.map