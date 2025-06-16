const vscode = require("vscode");

const unicodeBidiRegex = /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g;

module.exports = async function fixB613(document, range) {
  const line = document.lineAt(range.start.line);
  const originalText = line.text;

  const cleanedText = originalText.replace(unicodeBidiRegex, "");

  if (cleanedText === originalText) return; // אין מה לתקן

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, cleanedText);

  vscode.window.showWarningMessage("🚨 TrojanSource Unicode control characters removed.");

  return edit;
};
