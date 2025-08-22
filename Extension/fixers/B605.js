// fixers/B605.js
const vscode = require("vscode");

module.exports = async function fixB605(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  const shellMatch = lineText.match(/shell\s*=\s*True/);
  const cmdMatch = lineText.match(/["'](.+?)["']/);

  if (shellMatch && cmdMatch && !lineText.includes("|") && !lineText.includes(">") && !lineText.includes("+")) {
    const parts = cmdMatch[1].split(" ").map(p => `"${p}"`).join(", ");
    let newLine = lineText.replace(shellMatch[0], "");
    newLine = newLine.replace(cmdMatch[0], `[${parts}]`);
    edit.replace(document.uri, document.lineAt(range.start.line).range, newLine);
  } else {
    vscode.window.showWarningMessage("⚠️ הפקודה מורכבת מדי – לא מבוצע תיקון אוטומטי.");
  }

  return edit;
};
