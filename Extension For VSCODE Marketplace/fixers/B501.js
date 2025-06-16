const vscode = require("vscode");

module.exports = async function fixB501(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const lineText = line.text;

  // בודק אם השורה מכילה את verify=False
  if (!lineText.includes("verify=False")) {
    vscode.window.showWarningMessage("⚠️ לא נמצא verify=False. אין מה לתקן אוטומטית.");
    return edit;
  }

  // מבצע את ההחלפה ל־verify=True
  const fixedLine = lineText.replace("verify=False", "verify=True");
  edit.replace(document.uri, line.range, fixedLine);

  return edit;
};
