const vscode = require("vscode");

module.exports = async function fixB701(document, range) {
  const line = document.lineAt(range.start.line);
  const originalText = line.text;

  if (!originalText.includes("autoescape=False")) return;

  const fixedLine = originalText.replace("autoescape=False", "autoescape=True");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, fixedLine);

  vscode.window.showInformationMessage("✅ שונה autoescape ל־True למניעת XSS.");

  return edit;
};
