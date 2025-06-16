// fixers/B113.js
const vscode = require("vscode");

module.exports = async function fixB113(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // תנאי: רק אם אין כבר timeout=
  const hasTimeout = lineText.includes("timeout=");
  const isRequestLine = /requests\.(get|post|put|delete|head)\s*\(.*\)/.test(lineText);

  if (hasTimeout || !isRequestLine) {
    vscode.window.showWarningMessage("⏱️ אי אפשר להוסיף timeout – או שכבר קיים או שהשורה מורכבת מדי.");
    return edit;
  }

  // ננסה להוסיף timeout=5 בצורה פשוטה
  const insertionIndex = lineText.lastIndexOf(")");
  if (insertionIndex === -1) return edit;

  const newText = lineText.slice(0, insertionIndex) + ", timeout=5" + lineText.slice(insertionIndex);
  const rangeToReplace = new vscode.Range(
    new vscode.Position(range.start.line, 0),
    new vscode.Position(range.start.line, lineText.length)
  );

  edit.replace(document.uri, rangeToReplace, newText);
  return edit;
};
