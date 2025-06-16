// fixers/B112.js
const vscode = require("vscode");

/**
 * תיקון אוטומטי ל־try/except שמכיל רק continue
 * מחליף אותו ב־except עם print ואזהרה.
 */
module.exports = async function fixB112(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineNumber = range.start.line;

  const originalLine = document.lineAt(lineNumber).text;

  const lines = [];

  // חיפוש שורות של try+except+continue באותו בלוק פשוט
  let i = lineNumber;
  while (i < document.lineCount) {
    const lineText = document.lineAt(i).text.trim();

    lines.push({ number: i, text: lineText });

    if (lineText.startsWith("except") && document.lineAt(i + 1).text.trim() === "continue") {
      break;
    }
    i++;
  }

  const tryLine = lines.find(l => l.text.trim().startsWith("try"));
  const exceptLine = lines.find(l => l.text.trim().startsWith("except"));
  const continueLine = lines.find(l => l.text.trim() === "continue");

  // תנאי לתיקון: מבנה try/except/continue פשוט
  if (tryLine && exceptLine && continueLine) {
    const indent = document.lineAt(continueLine.number).firstNonWhitespaceCharacterIndex;
    const indentStr = " ".repeat(indent);

    const fixedLine = `${indentStr}print("⚠️ Exception occurred, skipping iteration")  # TODO: handle exception properly\n${indentStr}continue`;

    // החלפה של שורת continue בשורת print + continue
    edit.replace(document.uri, new vscode.Range(continueLine.number, 0, continueLine.number, continueLine.text.length), fixedLine);
  }

  return edit;
};
