// fixers/B607.js
const vscode = require("vscode");

const knownCommands = {
  "ls": "/bin/ls",
  "cat": "/bin/cat",
  "rm": "/bin/rm",
  "echo": "/bin/echo",
  "sh": "/bin/sh",
  "bash": "/bin/bash"
};

module.exports = async function fixB607(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // חיפוש של פקודה בתור מחרוזת ישירה
  const regex = /(["'])(\s*)(ls|cat|rm|echo|sh|bash)(\s.*?)\1/;
  const match = lineText.match(regex);

  if (match) {
    const fullCommand = match[3];
    const args = match[4] || "";
    const fullPath = knownCommands[fullCommand];

    if (fullPath) {
      const fixedCommand = `"${fullPath}${args}"`;
      const newText = lineText.replace(regex, fixedCommand);
      const fullRange = new vscode.Range(
        range.start.line,
        0,
        range.start.line,
        lineText.length
      );
      edit.replace(document.uri, fullRange, newText);

      vscode.window.showInformationMessage(
        `🔧 B607: הוחלפה הפקודה '${fullCommand}' לנתיב מלא (${fullPath})`
      );
    }
  } else {
    vscode.window.showWarningMessage(
      "⚠️ B607: לא ניתן להחיל תיקון אוטומטי – הפקודה אינה במבנה פשוט."
    );
  }

  return edit;
};
