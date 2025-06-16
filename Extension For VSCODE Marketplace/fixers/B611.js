const vscode = require("vscode");

module.exports = async function fixB611(document, range) {
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // נזהר מביטויים דינמיים – לא נתקן
  if (text.includes("%") || text.includes("+") || text.includes("user_input")) {
    return;
  }

  // ננסה להחליף raw לשימוש ב־filter
  const newText = text.replace(/\.raw\(["'].*is_active\s*=\s*1["']\)/, ".filter(is_active=True)");

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, newText);
  return edit;
};
