// fixers/B509.js
const vscode = require("vscode");

/**
 * B509: SNMP weak crypto → החלפה של MD5/DES באלגוריתמים חזקים יותר
 */
module.exports = async function fixB509(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  let modified = false;
  let fixedLine = lineText;

  if (/AuthProtocol\s*:\s*['"]MD5['"]/.test(fixedLine)) {
    fixedLine = fixedLine.replace(/AuthProtocol\s*:\s*['"]MD5['"]/, "AuthProtocol: 'SHA'");
    modified = true;
  }

  if (/PrivProtocol\s*:\s*['"]DES['"]/.test(fixedLine)) {
    fixedLine = fixedLine.replace(/PrivProtocol\s*:\s*['"]DES['"]/, "PrivProtocol: 'AES'");
    modified = true;
  }

  if (modified) {
    const fullRange = new vscode.Range(
      new vscode.Position(range.start.line, 0),
      new vscode.Position(range.start.line, lineText.length)
    );
    edit.replace(document.uri, fullRange, fixedLine);
  } else {
    vscode.window.showWarningMessage(
      "⚠️ לא ניתן לתקן אוטומטית – השורה אינה כוללת שימוש ב־MD5 או DES או שהמבנה מורכב."
    );
  }

  return edit;
};
