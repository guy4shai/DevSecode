const vscode = require("vscode");

/**
 * Auto-fix for Bandit rule B106: hardcoded_password_funcarg
 * Removes default hardcoded password values from function parameters if simple.
 */
module.exports = async function fixB106(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // תנאי בסיס: זיהוי פרמטר בשם password עם ערך ברירת מחדל
  const regex = /(\bpassword\s*=\s*)["'][^"']*["']/;

  if (regex.test(text)) {
    const fixedLine = text.replace(regex, `$1""`);
    edit.replace(document.uri, line.range, fixedLine);

    vscode.window.showInformationMessage(
      "🔐 Default password in function argument was removed for safety."
    );
  } else {
    vscode.window.showWarningMessage(
      "⚠️ Could not auto-fix B106 – the line is not in a simple format."
    );
  }

  return edit;
};
