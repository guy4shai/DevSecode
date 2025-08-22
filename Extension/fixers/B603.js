// fixers/B603.js
const vscode = require("vscode");

module.exports = async function fixB603(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line).text;

  const match = line.match(/subprocess\.Popen\(\s*["'](.+?)["']\s*\)/);
  if (match) {
    const commandParts = match[1].split(" ").map(s => `"${s}"`).join(", ");
    const newLine = line.replace(match[0], `subprocess.Popen([${commandParts}])`);
    edit.replace(document.uri, document.lineAt(range.start.line).range, newLine);
  } else {
    vscode.window.showWarningMessage("⚠️ לא ניתן לתקן אוטומטית – הפקודה אינה פשוטה.");
  }

  return edit;
};
