const vscode = require("vscode");

/**
 * Auto-fix for B608: hardcoded_sql_expressions
 * תנאי: משתמש ב־sqlite3 ושאילתה עם חיבור פשוט של מחרוזת + משתנה.
 */
module.exports = async function fixB608(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const fullText = document.getText();

  // בדיקה: האם יש import sqlite3
  const hasSQLiteImport = /import\s+sqlite3|from\s+sqlite3\s+import/.test(fullText);
  if (!hasSQLiteImport) {
    vscode.window.showWarningMessage("⚠️ B608: לא נמצא 'import sqlite3' בקובץ – לא מתקן אוטומטית.");
    return edit;
  }

  const line = document.lineAt(range.start.line);
  const lineText = line.text;

  // תנאי פשוט: query = "... " + variable
  const match = lineText.match(/(const|let|var)?\s*query\s*=\s*"([^"]+)"\s*\+\s*(\w+)/);
  if (!match) {
    vscode.window.showWarningMessage("⚠️ B608: נתמך רק בשאילתות עם חיבור פשוט של משתנה אחד.");
    return edit;
  }

  const paramQuery = match[2] + "?";
  const variable = match[3];
  const newLine = `query = "${paramQuery}"`;
  edit.replace(document.uri, line.range, newLine);

  // בדיקה אם השורה הבאה היא cursor.execute(query)
  const nextLineNumber = range.start.line + 1;
  if (nextLineNumber < document.lineCount) {
    const nextLine = document.lineAt(nextLineNumber);
    const execMatch = nextLine.text.match(/cursor\.execute\(\s*query\s*\)/);

    if (execMatch) {
      const updatedExec = `cursor.execute(query, (${variable},))`;
      edit.replace(document.uri, nextLine.range, updatedExec);
    } else {
      vscode.window.showWarningMessage("⚠️ B608: לא נמצא 'cursor.execute(query)' מיד לאחר השאילתה – שימי לב לבדוק זאת.");
    }
  }

  return edit;
};
