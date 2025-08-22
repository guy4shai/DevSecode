// fixers/B508.js
const vscode = require("vscode");

/**
 * מזהה ומתקן שימוש ב־SNMP v1/v2c → SNMP v3 במבנים פשוטים בלבד.
 */
module.exports = async function fixB508(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // בודק אם מדובר בשורה פשוטה שניתן לתקן
  if (/netsnmp\.Session\s*\(.*Version\s*=\s*(1|2c)/.test(lineText)) {
    const fixedLine = lineText
      .replace(/Version\s*=\s*(1|2c)/, "Version=3")
      .replace(/Community\s*=\s*['"].+?['"]/, "SecLevel='authPriv', SecName='yourUser'");

    const fullRange = new vscode.Range(
      new vscode.Position(range.start.line, 0),
      new vscode.Position(range.start.line, lineText.length)
    );

    edit.replace(document.uri, fullRange, fixedLine);
  } else {
    vscode.window.showWarningMessage(
      "⚠️ לא בוצע תיקון אוטומטי – המבנה של השורה מורכב מדי. תקן ידנית את השימוש ב־SNMP v1/v2c ל־v3."
    );
  }

  return edit;
};
