const vscode = require("vscode");

module.exports = async function fixB505(document, range) {
  const edit = new vscode.WorkspaceEdit();
  const line = document.lineAt(range.start.line);
  const text = line.text;

  // מחליף RSA.generate(1024) ב־RSA.generate(2048)
  if (text.includes("generate") && text.includes("1024")) {
    const fixedText = text.replace("1024", "2048");
    edit.replace(document.uri, line.range, fixedText);
    return edit;
  }

  // מחליף key_size=1024 ב־key_size=2048
  if (text.includes("key_size") && text.includes("1024")) {
    const fixedText = text.replace("key_size=1024", "key_size=2048");
    edit.replace(document.uri, line.range, fixedText);
    return edit;
  }

  // אם לא ניתן לתקן – נציג הערה בלבד
  vscode.window.showWarningMessage("⚠️ לא ניתן לתקן את B505 באופן אוטומטי. בדוק את הקוד ידנית.");
  return edit;
};
