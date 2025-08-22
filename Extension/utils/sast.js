// const vscode = require("vscode");
// const path = require("path");
// const fs = require("fs");
// const cp = require("child_process");
// const util = require("util");

// async function runBanditScan(rootPath, tempDir, context) {
//     const banditReportPath = path.join(tempDir, "bandit_report.json");
//     const banditCommand = `bandit -r "${rootPath}" --exclude "${rootPath}/node_modules,${rootPath}/venv" -f json -o "${banditReportPath}"`;

//     const exec = util.promisify(cp.exec);

//     try {
//         await exec(banditCommand, { maxBuffer: 1024 * 1000 });
//         vscode.window.showInformationMessage("✅ Bandit scan completed.");
//     } catch (e) {
//         console.error("Bandit error:", e.stderr || e);
//     }

//     try {
//         const banditRaw = fs.readFileSync(banditReportPath, "utf8");
//         const banditData = JSON.parse(banditRaw);
//         currentBanditFindings = banditData.results || [];
//         vscode.window.showInformationMessage("✅ Bandit report loaded.");
//     } catch (err) {
//         vscode.window.showWarningMessage("⚠️ Failed to parse bandit_report.json.");
//         console.warn("Bandit parsing error:", err);
//         currentBanditFindings = [];
//     }

//     registerBanditAutoFixes(context);
//     showBanditDiagnostics(context, () => tempDir);
//     return currentBanditFindings;
// }

// const {
//     showBanditDiagnostics,
//     registerBanditAutoFixes,
// } = require("../banditAutoFixer");

// module.exports = {
//     runBanditScan,
// };


// utils/sast.js
const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const cp = require("child_process");
const util = require("util");

const { showBanditDiagnostics, registerBanditAutoFixes } = require("../banditAutoFixer");

async function runBanditScan(rootPath, tempDir, context) {
  const banditReportPath = path.join(tempDir, "bandit_report.json");
  const banditCommand = `bandit -r "${rootPath}" --exclude "${rootPath}/node_modules,${rootPath}/venv" -f json -o "${banditReportPath}"`;

  const exec = util.promisify(cp.exec);

  try {
    await exec(banditCommand, { maxBuffer: 1024 * 1000 });
    vscode.window.showInformationMessage("✅ Bandit scan completed.");
  } catch (e) {
    console.error("Bandit error:", e.stderr || e);
  }

  let findings = [];
  try {
    const banditRaw = fs.readFileSync(banditReportPath, "utf8");
    const banditData = JSON.parse(banditRaw);
    findings = Array.isArray(banditData?.results) ? banditData.results : [];
    vscode.window.showInformationMessage("✅ Bandit report loaded.");
  } catch (err) {
    vscode.window.showWarningMessage("⚠️ Failed to parse bandit_report.json.");
    console.warn("Bandit parsing error:", err);
  }

  registerBanditAutoFixes(context);
  showBanditDiagnostics(context, () => tempDir);

  return findings; // ← מחזירים תוצאה, לא כותבים לשום גלובלי
}

module.exports = { runBanditScan };
