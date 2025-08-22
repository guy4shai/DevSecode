const vscode = require("vscode");

module.exports = async function fixB614(document, range) {
  const line = document.lineAt(range.start.line);
  const originalText = line.text;

  if (!originalText.includes("torch.load")) return;

  const comment = "# ⚠️ torch.load עלול להיות לא בטוח. שקול להשתמש ב־torch.jit.load או לבדוק את מקור הקובץ.\n";
  const newText = comment + originalText;

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, line.range, newText);

  vscode.window.showWarningMessage("🛡️ נוסף הסבר בטיחותי לשימוש ב־torch.load.");

  return edit;
};
