const vscode = require("vscode");

module.exports = async function fixB612(document, range) {
  const line = document.lineAt(range.start.line);
  const text = line.text;

  if (!text.includes("logging.config.listen")) return;

  // תיקן רק אם רואים 0.0.0.0 או כתובת ריקה
  const fixedText = text
    .replace("('0.0.0.0'", "('127.0.0.1'")
    .replace("('',", "('127.0.0.1',");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, fixedText);
  return edit;
};
