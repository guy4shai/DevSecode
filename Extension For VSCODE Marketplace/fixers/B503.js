const vscode = require("vscode");

/**
 * תיקון אוטומטי ל־B503 – הוספת אימות לאובייקט SSLContext.
 */
module.exports = async function fixB503(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  const match = text.match(/(\w+)\s*=\s*ssl\.create_default_context\(\)/);
  if (!match) return edit;

  const varName = match[1];
  const insertionLine = range.start.line + 1;

  const insertText = `${varName}.check_hostname = True\n${varName}.verify_mode = ssl.CERT_REQUIRED\n`;
  const insertPosition = new vscode.Position(insertionLine, 0);

  edit.insert(document.uri, insertPosition, insertText);
  return edit;
};
