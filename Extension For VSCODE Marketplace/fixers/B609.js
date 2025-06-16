const vscode = require("vscode");

/**
 * ✅ תיקון אוטומטי ל־B609 (linux_commands_wildcard_injection)
 * מחליף os.system("rm " + pattern) ב־glob + os.remove
 */
module.exports = async function fixB609(document, range) {
  const line = document.lineAt(range.start.line);
  const text = line.text;

  const pattern = /os\.system\(["']rm\s\+\s*(.+)["']\)/;

  const match = text.match(pattern);
  if (!match) return;

  const target = match[1].trim();

  const indent = line.firstNonWhitespaceCharacterIndex;
  const indentStr = " ".repeat(indent);

  const newCode = [
    `import glob`,
    `import os`,
    ``,
    `files = glob.glob(${target})`,
    `for f in files:`,
    `    os.remove(f)`
  ];

  const edit = new vscode.WorkspaceEdit();
  const fullRange = new vscode.Range(line.range.start, line.range.end);
  edit.replace(document.uri, fullRange, newCode.map((l, i) => (i === 0 ? indentStr + l : l)).join("\n"));
  return edit;
};
