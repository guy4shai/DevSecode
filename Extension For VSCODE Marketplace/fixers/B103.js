// fixers/B103.js

const vscode = require("vscode");

/**
 * תיקון אוטומטי עבור B103 – שימוש ב־chmod עם הרשאות לא בטוחות (0o777)
 * מחליף את ההרשאה ל־0o600 רק אם נמצא מבנה ישיר.
 */
async function fixB103(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const originalLine = document.getText(range);

  // בדיקה: האם השורה כוללת שימוש ישיר ב־chmod עם 0o777?
  const match = originalLine.match(/chmod\s*\(([^,]+),\s*0o777\s*\)/);

  if (match) {
    // החלפת 0o777 ל־0o600
    const fixedLine = originalLine.replace(/0o777/, "0o600");

    edit.replace(document.uri, range, fixedLine);
    return edit;
  } else {
    // לא בוצע תיקון כי זה לא מבנה פשוט
    vscode.window.showWarningMessage("⚠️ B103 לא תוקן אוטומטית – המבנה לא מתאים לתיקון בטוח.");
    return edit; // מחזיר אובייקט ריק – לא תוקן
  }
}

module.exports = fixB103;
