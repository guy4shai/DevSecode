const vscode = require("vscode");

/**
 * B109 - מוסיף secret=True לפרמטרים רגישים בקונפיגורציה (StrOpt)
 */
module.exports = async function fixB109(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const lineText = document.lineAt(range.start.line).text;

  // נוודא שמדובר בקריאה ל־StrOpt / register_opt עם שם שכולל "password" או "secret"
  const sensitivePattern = /StrOpt\(\s*['"]?(.*?(password|secret).*?)['"]?/i;

  if (sensitivePattern.test(lineText)) {
    // האם כבר קיים secret=True?
    if (!lineText.includes("secret=True")) {
      const insertPos = lineText.lastIndexOf(")");
      if (insertPos !== -1) {
        const newText = lineText.slice(0, insertPos) + ", secret=True" + lineText.slice(insertPos);
        const rangeToReplace = new vscode.Range(
          new vscode.Position(range.start.line, 0),
          new vscode.Position(range.start.line, lineText.length)
        );
        edit.replace(document.uri, rangeToReplace, newText);
      }
    }
  }

  return edit;
};
