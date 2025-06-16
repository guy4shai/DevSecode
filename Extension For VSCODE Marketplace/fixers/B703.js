const vscode = require("vscode");

module.exports = async function fixB703(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // נזהה רק את השימוש הישיר בפונקציה
  const regex = /mark_safe\((.+)\)/;
  const match = lineText.match(regex);

  if (match) {
    const replacement = `escape(${match[1]})`;
    const fullRange = new vscode.Range(
      range.start.line,
      lineText.indexOf("mark_safe"),
      range.start.line,
      lineText.length
    );
    edit.replace(document.uri, fullRange, replacement);

    vscode.window.showInformationMessage("🔐 mark_safe הוחלף ב־escape לצורך אבטחה.");
    return edit;
  }

  vscode.window.showWarningMessage("⚠️ לא ניתן להחיל תיקון אוטומטי על mark_safe במקרה זה.");
  return edit;
};
