// fixers/B601.js
const vscode = require("vscode");

module.exports = async function fixB601(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // נמצא את שורת ה-client ונוסיף אחריה set_missing_host_key_policy
  if (/paramiko\.SSHClient\(\)/.test(text)) {
    const nextLine = range.start.line + 1;
    const insertPos = new vscode.Position(nextLine, 0);
    const insertion = `client.set_missing_host_key_policy(paramiko.RejectPolicy())\n`;
    edit.insert(document.uri, insertPos, insertion);
  } else {
    vscode.window.showWarningMessage("⚠️ לא ניתן לתקן אוטומטית – אין שימוש ברור ב־SSHClient.");
  }

  return edit;
};
