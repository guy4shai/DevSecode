const vscode = require("vscode");

/**
 * תיקון אוטומטי ל־B502 – שימוש ב־ssl.PROTOCOL_SSLv3 או גרסאות ישנות אחרות.
 * מחליף בפרוטוקול בטוח יותר (TLS_CLIENT או TLSv1_2).
 */
module.exports = async function fixB502(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const oldText = document.getText(range);

  // רק אם הקוד כולל פרוטוקול בעייתי – נבצע תיקון
  const fixedText = oldText
    .replace(/ssl\.PROTOCOL_SSLv2/g, "ssl.PROTOCOL_TLS_CLIENT")
    .replace(/ssl\.PROTOCOL_SSLv3/g, "ssl.PROTOCOL_TLS_CLIENT")
    .replace(/ssl\.PROTOCOL_TLSv1(_0)?/g, "ssl.PROTOCOL_TLS_CLIENT")
    .replace(/ssl\.PROTOCOL_TLSv1_1/g, "ssl.PROTOCOL_TLS_CLIENT");

  if (oldText !== fixedText) {
    edit.replace(document.uri, range, fixedText);
  }

  return edit;
};
