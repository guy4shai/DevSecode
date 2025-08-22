const vscode = require("vscode");

module.exports = async function fixB704(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  const regex = /Markup\((.+)\)/;
  const match = lineText.match(regex);

  if (match) {
    const replacement = `escape(${match[1]})`;
    const fullRange = new vscode.Range(
      range.start.line,
      lineText.indexOf("Markup"),
      range.start.line,
      lineText.length
    );
    edit.replace(document.uri, fullRange, replacement);

    vscode.window.showInformationMessage("🔐 Markup() הוחלף ב־escape למניעת XSS.");
    return edit;
  }

  vscode.window.showWarningMessage("⚠️ לא ניתן לבצע תיקון אוטומטי על Markup() במקרה זה.");
  return edit;
};
