const vscode = require("vscode");

module.exports = async function fixB610(document, range) {
  const line = document.lineAt(range.start.line);
  const text = line.text;

  if (!text.includes(".extra(") || text.includes("user") || text.includes("+")) {
    // אם יש ביטוי דינמי – אל תתקן
    return;
  }

  const newText = text.replace(/\.extra\((.*?)\)/, ".annotate(value=Value(1))");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, newText);
  return edit;
};
