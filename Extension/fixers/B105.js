const vscode = require("vscode");

/**
 * תיקון אוטומטי לחוק B105 – Hardcoded password string
 * ➤ מחליף מחרוזות "סיסמאות" במחרוזת ריקה ("") רק במבנים פשוטים
 */
module.exports = async function fixB105(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // התאמה לשורות מהצורה: var_name = "some_password"
  const passwordRegex = /^\s*(\w*(password|passwd|pwd)\w*)\s*=\s*["'].*["']/i;
  const match = lineText.match(passwordRegex);

  if (match) {
    const fullLineRange = new vscode.Range(
      range.start.line, 0,
      range.start.line, lineText.length
    );

    const variableName = match[1];
    const fixedLine = `${variableName} = ""`;

    edit.replace(document.uri, fullLineRange, fixedLine);

    vscode.window.showInformationMessage(
      `🛡️ B105 תוקן: הסיסמה הוסרה מהקוד (הומרה למחרוזת ריקה)`
    );
  } else {
    vscode.window.showWarningMessage(
      `⚠️ B105 לא תוקן אוטומטית – לא נמצא מבנה פשוט שניתן להמיר`
    );
  }

  return edit;
};
