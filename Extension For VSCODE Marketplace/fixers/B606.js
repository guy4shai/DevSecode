// fixers/B606.js
const vscode = require("vscode");

module.exports = async function fixB606(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // נוודא שהקריאה אינה מכילה קלט ממשתמש (פשטני)
  const isSafe = !lineText.includes("input") && !lineText.includes("format(") && !lineText.includes("+");

  if (isSafe) {
    const newLine = lineText.replace(/\)\s*$/, ", stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)");
    edit.replace(document.uri, document.lineAt(range.start.line).range, newLine);
  } else {
    vscode.window.showWarningMessage("⚠️ קלט לא בטוח – לא בוצע תיקון אוטומטי.");
  }

  return edit;
};
