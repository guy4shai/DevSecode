const vscode = require("vscode");

module.exports = async function fixB102(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // חיפוש exec עם תוכן בתוך גרשיים
  const execMatch = text.match(/exec\((['"`])(.*?)\1\)/);
  if (!execMatch) {
    vscode.window.showWarningMessage("⚠️ לא זוהה תוכן לתיקון בתוך exec().");
    return edit;
  }

  const rawContent = execMatch[2].trim();

  // בדיקה אם זו רשימה / מילון / מספר - ביטויים בטוחים יחסית
  const isSafeStructure = /^(\[.*\]|\{.*\}|\d+(\.\d+)?|".*"|'.*')$/.test(rawContent);
  if (!isSafeStructure) {
    vscode.window.showWarningMessage("⚠️ זוהה קוד מורכב ב־exec – לא בוצע תיקון אוטומטי.");
    return edit;
  }

  // החלפה ב־ast.literal_eval
  const newText = text.replace(/exec\((['"`]).*?\1\)/, `ast.literal_eval(${execMatch[1]}${rawContent}${execMatch[1]})`);

  edit.replace(document.uri, line.range, newText);
  return edit;
};
