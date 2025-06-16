const vscode = require("vscode");

/**
 * B101: assert used → convert to if-not + raise AssertionError
 */
module.exports = async function (document, range) {
  const line = document.lineAt(range.start.line);
  const assertCode = line.text.trim();

  const condition = assertCode.replace(/^assert\s+/, "").trim();
  const indent = line.text.match(/^\s*/)[0];

  const replacement =
    `${indent}if not ${condition}:\n` +
    `${indent}    raise AssertionError("${condition}")`;

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, replacement);

  return edit;
};
