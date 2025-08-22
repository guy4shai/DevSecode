const vscode = require("vscode");

/**
 * B324: תיקון שימושים לא בטוחים ב־hashlib (md5, sha1, וכו')
 */
module.exports = async function (document, range) {
  const line = document.lineAt(range.start.line);
  let fixed = line.text;

  // החלפות ישירות
  fixed = fixed.replace(/hashlib\.md5/g, "hashlib.sha256");
  fixed = fixed.replace(/hashlib\.sha1/g, "hashlib.sha256");

  // החלפות עם new()
  fixed = fixed.replace(/hashlib\.new\(["']md5["']/g, 'hashlib.new("sha256"');
  fixed = fixed.replace(/hashlib\.new\(["']sha1["']/g, 'hashlib.new("sha256"');

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, fixed);
  return edit;
};
