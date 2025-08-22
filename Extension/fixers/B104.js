const vscode = require("vscode");

/**
 * תיקון אוטומטי ל־B104 - שינוי host מ־"0.0.0.0" ל־"127.0.0.1"
 */
module.exports = async function fixB104(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // רק אם יש מחרוזת "host='0.0.0.0'" או "host=\"0.0.0.0\""
  const hostRegex = /(host\s*=\s*)(["'])0\.0\.0\.0\2/;

  const match = lineText.match(hostRegex);
  if (match) {
    const fixedLine = lineText.replace(hostRegex, `$1$2${"127.0.0.1"}$2`);
    const fullRange = new vscode.Range(
      range.start.line,
      0,
      range.start.line,
      lineText.length
    );
    edit.replace(document.uri, fullRange, fixedLine);
  } else {
    vscode.window.showWarningMessage("⚠️ לא ניתן לתקן אוטומטית את B104 – מבנה שורה לא נתמך.");
  }

  return edit;
};
