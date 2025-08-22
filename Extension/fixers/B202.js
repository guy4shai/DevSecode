// fixers/B202.js
const vscode = require("vscode");

module.exports = async function fixB202(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineNum = range.start.line;
  const lineText = document.lineAt(lineNum).text;

  // נתקן רק extractall פשוט
  if (!lineText.includes(".extractall")) {
    vscode.window.showWarningMessage("❌ לא נמצא extractall. לא מתבצע תיקון.");
    return edit;
  }

  // מחליפים את extractall בשורת קריאה ל־safe_extract
  const newText = lineText.replace(/\.extractall\s*\((.*?)\)/, 'safe_extract(tar, $1)');

  // מוסיפים קוד safe_extract (למעלה בקובץ או בקובץ utils)
  const safeExtractCode = `
import os

def is_within_directory(directory, target):
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])

def safe_extract(tar, path=".", members=None):
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not is_within_directory(path, member_path):
            raise Exception("❌ Path Traversal Detected!")
    tar.extractall(path, members)\n`;

  edit.insert(document.uri, new vscode.Position(0, 0), safeExtractCode);
  edit.replace(document.uri, new vscode.Range(lineNum, 0, lineNum, lineText.length), newText);

  return edit;
};
