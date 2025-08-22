const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

function getTempScanDir() {
  const workspacePath =
    vscode.workspace.workspaceFolders?.[0].uri.fsPath || process.cwd();
  return path.join(os.tmpdir(), "devsecode", path.basename(workspacePath));
}

async function runDastScan(targetUrl, outputFilePath) {
  return new Promise((resolve, reject) => {
    const zapCommand = `zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" --spider --scanners all -o json -r ${outputFilePath} ${targetUrl}`;

    cp.exec(zapCommand, (error, stdout, stderr) => {
      if (error) {
        console.error("ZAP Error:", stderr);
        reject(stderr);
      } else {
        console.log("ZAP Output:", stdout);
        resolve(outputFilePath);
      }
    });
  });
}

module.exports = {
  runDastScan,
  getTempScanDir,
};
