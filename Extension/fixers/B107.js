const vscode = require("vscode");

/**
 * Auto-fix for Bandit rule B107: hardcoded_password_default
 * Replaces default password values in simple function parameters.
 */
module.exports = async function fixB107(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // מחפש מחרוזת כמו: password="something"
  const regex = /(\bpassword\s*=\s*)["'][^"']*["']/i;

  if (regex.test(text)) {
    const fixedLine = text.replace(regex, `$1""`);
    edit.replace(document.uri, line.range, fixedLine);

    vscode.window.showInformationMessage(
      "🔐 Removed hardcoded default password value in parameter."
    );
  } else {
    vscode.window.showWarningMessage(
      "⚠️ Could not auto-fix B107 – the structure is too complex."
    );
  }

  return edit;
};
