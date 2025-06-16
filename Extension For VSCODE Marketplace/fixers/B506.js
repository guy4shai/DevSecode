const vscode = require("vscode");

/**
 * מחליף שימושים לא בטוחים ב־yaml.load בקוד פשוט
 * לדוגמה:
 * yaml.load(f)  ➜  yaml.load(f, Loader=yaml.SafeLoader)
 */
module.exports = async function fixB506(document, range) {
  const edit = new vscode.WorkspaceEdit();

  const line = document.lineAt(range.start.line);
  let fixedLine = line.text;

  // ודא שזו קריאה ל־yaml.load ואין Loader כבר
  const regex = /yaml\.load\s*\(([^)]*)\)/;
  const hasLoader = /Loader\s*=/.test(line.text);

  if (regex.test(line.text) && !hasLoader) {
    // מוסיף את הטיעון Loader=yaml.SafeLoader
    fixedLine = line.text.replace(regex, (match, args) => {
      const newArgs = args.trim() ? `${args.trim()}, Loader=yaml.SafeLoader` : "Loader=yaml.SafeLoader";
      return `yaml.load(${newArgs})`;
    });

    edit.replace(document.uri, line.range, fixedLine);
  }

  return edit;
};
