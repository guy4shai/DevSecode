const vscode = require("vscode");

/**
 * תיקון אוטומטי ל־B108: hardcoded_tmp_directory
 */
module.exports = async function fixB108(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.getText(range);

  const tmpRegexUnix = /["']\/tmp\/([^"']+)["']/;
  const tmpRegexWin = /["']C:\\\\temp\\\\([^"']+)["']/i;

  let filename = null;
  let newLine = lineText;

  if (tmpRegexUnix.test(lineText)) {
    filename = lineText.match(tmpRegexUnix)[1];
  } else if (tmpRegexWin.test(lineText)) {
    filename = lineText.match(tmpRegexWin)[1];
  }

  if (!filename) {
    vscode.window.showWarningMessage("⚠️ לא נמצא נתיב /tmp לתיקון.");
    return edit;
  }

  const replacement = `os.path.join(tempfile.gettempdir(), "${filename}")`;
  newLine = lineText.replace(/["'](\/tmp|C:\\\\temp)\/[^"']+["']/i, replacement);

  const position = new vscode.Position(range.start.line, 0);
  edit.replace(document.uri, new vscode.Range(position, position.translate(0, lineText.length)), newLine);

  // בדיקה אם יש imports בקובץ
  const fullText = document.getText();
  const importLines = fullText.split("\n").filter(line => line.startsWith("import "));
  const hasOS = importLines.some(line => line.includes("os"));
  const hasTempfile = importLines.some(line => line.includes("tempfile"));

  // מוסיפים import במידת הצורך, אחרי השורה האחרונה של import
  const lines = fullText.split("\n");
  let insertLine = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith("import") || lines[i].startsWith("from")) {
      insertLine = i + 1;
    }
  }

  if (!hasOS) {
    edit.insert(document.uri, new vscode.Position(insertLine, 0), `import os\n`);
    insertLine++;
  }

  if (!hasTempfile) {
    edit.insert(document.uri, new vscode.Position(insertLine, 0), `import tempfile\n`);
  }

  vscode.window.showInformationMessage(`✅ B108 תוקן: נתיב tmp הוחלף + נוספו imports אם נדרש.`);

  return edit;
};
