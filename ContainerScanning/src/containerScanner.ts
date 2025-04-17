import * as vscode from 'vscode';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

interface TrivyVulnerability {
  VulnerabilityID: string;
  Title: string;
  Description: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Severity: string;
  PrimaryURL?: string;
}
interface TrivyResult { Target: string; Vulnerabilities?: TrivyVulnerability[]; }
interface TrivyScanResult { ArtifactName: string; Results: TrivyResult[]; }

export class ContainerScanner {
  private cacheDir: string;
  constructor(
    private context: vscode.ExtensionContext,
    private diagnostics: vscode.DiagnosticCollection,
    private output: vscode.OutputChannel
  ) {
    this.cacheDir = path.join(context.globalStorageUri.fsPath, 'trivy-db');
    fs.mkdirSync(this.cacheDir, { recursive: true });
  }

  private async ensureDb(): Promise<void> {
    this.output.appendLine('Updating Trivy DB...');
    return new Promise(res => {
      const proc = spawn('trivy', ['db', 'update', '--cache-dir', this.cacheDir], { shell: true });
      proc.on('close', () => res());
    });
  }

  public async scanImage(image: string, dockerfileUri: vscode.Uri): Promise<string> {
    await this.ensureDb();
    const dir = path.dirname(dockerfileUri.fsPath) || process.cwd();
    const file = 'ContainerScanner_outputJson.json';
    const outPath = path.join(dir, file);

    this.output.appendLine(`Scanning image: ${image}`);
    return new Promise((resolve, reject) => {
      const proc = spawn(
        'trivy', ['image', '--format', 'json', '--cache-dir', this.cacheDir, '--output', outPath, image],
        { shell: true }
      );
      proc.on('error', err => reject(err));
      proc.on('close', async code => {
        if (code !== 0 && code !== 1) return reject(new Error(`Scan failed (${code})`));
        try {
          const raw = await fs.promises.readFile(outPath, 'utf8');
          const parsed: TrivyScanResult = JSON.parse(raw);
          // minimal JSON structure
          const allVulns = parsed.Results.reduce<TrivyVulnerability[]>((acc, r) => acc.concat(r.Vulnerabilities||[]), []);
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
            `CRITICAL: ${vulns.filter(v=>v.severity==='CRITICAL').length}, ` +
            `HIGH: ${vulns.filter(v=>v.severity==='HIGH').length}, ` +
            `MEDIUM: ${vulns.filter(v=>v.severity==='MEDIUM').length}, ` +
            `LOW: ${vulns.filter(v=>v.severity==='LOW').length}).`;
          const minimal = { summary, artifact: parsed.ArtifactName, vulnerabilities: vulns };
          await fs.promises.writeFile(outPath, JSON.stringify(minimal, null, 2));
          this.publishDiagnostics(parsed, dockerfileUri);
          this.output.appendLine(`Results saved to ${outPath}`);
          resolve(outPath);
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  private publishDiagnostics(res: TrivyScanResult, uri: vscode.Uri) {
    const diags: vscode.Diagnostic[] = [];
    const doc = vscode.workspace.textDocuments.find(d=>d.uri.fsPath===uri.fsPath);
    const line = doc?.getText().split(/\r?\n/).findIndex(l=>/^FROM\s+/.test(l))||0;
    res.Results.forEach(r=>r.Vulnerabilities?.forEach(v=>{
      const sev = v.Severity==='CRITICAL'||v.Severity==='HIGH'
        ? vscode.DiagnosticSeverity.Error
        : v.Severity==='MEDIUM'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;
      const msg = `${v.PkgName}@${v.InstalledVersion}→${v.VulnerabilityID}(${v.Severity})`;
      diags.push(new vscode.Diagnostic(new vscode.Range(line,0,line,0),msg,sev));
    }));
    this.diagnostics.set(uri, diags);
  }
}