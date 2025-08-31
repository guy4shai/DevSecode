const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

function resolveProjectName(config) {
  try {
    if (config?.projectName) return config.projectName;
    if (config?.workspacePath) return path.basename(config.workspacePath);
  } catch (_) {}
  return 'project';
}

function getSeverity(entropy) {
  if (entropy > 4.5) return { level: 'Critical', color: '#B33A3A' };
  if (entropy > 4.0) return { level: 'High', color: '#FF6F61' };
  if (entropy > 3.5) return { level: 'Medium', color: '#FFB347' };
  return { level: 'Low', color: '#FFC107' };
}

function getRecommendation(ruleID) {
  return `It is recommended to review uses of '${ruleID}', follow secure coding practices, and replace any exposed secrets with secure storage methods.`;
}

function getSeverityScore(level) {
  return { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 }[level] ?? 4;
}

function rgbToHex(rgbString) {
  const rgb = rgbString.match(/\d+/g);
  if (!rgb || rgb.length < 3) return "#000000";
  return (
    "#" +
    rgb
      .slice(0, 3)
      .map((v) => parseInt(v).toString(16).padStart(2, "0"))
      .join("")
  );
}
// --- Layout helpers ---
function getMargins(doc) {
  const m = (doc.options && doc.options.margins) || { top: 50, bottom: 50, left: 50, right: 50 };
  return m;
}
function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}



function normalizeFindings({ gitleaks = [], trivy = {}, bandit = {}, container = {} }) {
  const normalized = [];

  // --- Secrets (Gitleaks) ---
  (Array.isArray(gitleaks) ? gitleaks : []).forEach(f => {
    normalized.push({
      tool: 'Gitleaks',
      File: f.File,
      StartLine: f.StartLine,
      RuleID: f.RuleID,
      Description: f.Description,
      Match: f.Match,
      Entropy: f.Entropy
    });
  });

  // Helper for SCA/Trivy-style vulns
  const pushTrivy = (target, vuln) => {
    if (!vuln) return;
    normalized.push({
      tool: 'Trivy',
      File: target || vuln.Target || vuln.PkgName || vuln.PackageName || 'package',
      StartLine: 1,
      RuleID: vuln.VulnerabilityID || vuln.id,
      Description: vuln.Title || vuln.description || vuln.Description || 'Vulnerability',
      Match: vuln.PkgName || vuln.PackageName || '',
      Entropy: getEntropyFromSeverity(vuln.Severity || vuln.severity)
    });
  };

  // --- SCA (Trivy filesystem scan) ---
  if (Array.isArray(trivy?.Results)) {
    trivy.Results.forEach(r => (r.Vulnerabilities || []).forEach(v => pushTrivy(r.Target, v)));
  } else if (Array.isArray(trivy?.Vulnerabilities)) {
    trivy.Vulnerabilities.forEach(v => pushTrivy(trivy.Target, v));
  } else if (Array.isArray(trivy)) {
    // some tools give a flat array of vulns
    trivy.forEach(v => pushTrivy(v.Target, v));
  }

  // --- SAST (Bandit) ---
  (bandit?.results || []).forEach(item => {
    normalized.push({
      tool: 'Bandit',
      File: item.filename,
      StartLine: item.line_number,
      RuleID: item.test_id,
      Description: item.issue_text,
      Match: '',
      Entropy: getEntropyFromSeverity(item.issue_severity)
    });
  });

  // === Container Scanning (Trivy image scan) ===
  const pushContainer = (target, vuln) => {
    if (!vuln) return;
    normalized.push({
      tool: 'Container',
      File: target || vuln.Target || vuln.Image || vuln.PkgName || 'container-image',
      StartLine: 1,
      RuleID: vuln.VulnerabilityID || vuln.id,
      Description: vuln.Title || vuln.description || vuln.Description || 'Container vulnerability',
      Match: vuln.PkgName || vuln.pkgName || vuln.PackageName || '',
      Entropy: getEntropyFromSeverity(vuln.Severity || vuln.severity)
    });
  };

  if (Array.isArray(container?.Results)) {
    container.Results.forEach(r => (r.Vulnerabilities || []).forEach(v => pushContainer(r.Target, v)));
  } else if (Array.isArray(container?.Vulnerabilities)) {
    container.Vulnerabilities.forEach(v => pushContainer(container.Target, v));
  } else if (Array.isArray(container)) {
    container.forEach(v => pushContainer(v.Target, v));
  }
  // === end Container Scanning ===

  return normalized;
}


function getEntropyFromSeverity(sev) {
  switch (sev?.toLowerCase?.()) {
    case 'critical': return 5.0;
    case 'high': return 4.5;
    case 'medium': return 4.0;
    case 'low': return 3.0;
    default: return 1.0;
  }
}

function filterFindings(findings, config) {
  const selectedSeverities = config.selectedSeverities || ['Critical','High', 'Medium', 'Low'];
  const filtered = findings.filter(f => selectedSeverities.includes(getSeverity(f.Entropy).level));
  return config.sortBy === 'severity'
    ? filtered.sort((a, b) => getSeverityScore(getSeverity(a.Entropy).level) - getSeverityScore(getSeverity(b.Entropy).level))
    : filtered.sort((a, b) => (a.StartLine || 0) - (b.StartLine || 0));
}

function renderChartWithLegend(doc, chartData, headerText) {
  if (!chartData) return;

  // Normalize input
  const legendArray = Array.isArray(chartData.legend) ? chartData.legend : [];
  const dataUrl = chartData.image || chartData.dataUrl || chartData;
  if (!dataUrl || typeof dataUrl !== 'string') return;

  // Decode base64 PNG
  const base64 = dataUrl.replace(/^data:image\/png;base64,/, '');
  if (!base64) return;
  const imageBuffer = Buffer.from(base64, 'base64');

  // ---- Layout constants ----
  const { top, bottom, left, right } = getMargins(doc);
  const pageW = doc.page.width;
  const pageH = doc.page.height;

  const HEADER_SIZE       = 14;     // כותרת לגרף ("Findings by ...")
  const FONT_SIZE         = 11;     // טקסט מקרא
  const ROW_MIN           = 14;     // גובה מינימלי לשורה
  const ROW_GAP           = 2;      // רווח קטן בין פריטי מקרא
  const GAP_AFTER_HEADER  = 8;

  const LEGEND_COL_W      = 230;    // רוחב עמודת מקרא
  const LEGEND_COLS       = 2;      // כמה עמודות מקרא בעמוד

  const CHART_W           = 260;    // רוחב הגרף
  const CHART_H           = 260;    // גובה הגרף (אם הגרפים שלך לא ריבועיים – שנהי כאן)
  const CHART_FIT         = [CHART_W, CHART_H];

  // מיקומים: מקרא משמאל, גרף מימין – קו עליון משותף
  const legendX = left;
  const chartX  = pageW - right - CHART_W;

  // בדיקת מקום מינימלי לפני כותרת
  const minBlockHeight = HEADER_SIZE + GAP_AFTER_HEADER + ROW_MIN * 3;
  if (doc.y > pageH - bottom - minBlockHeight) {
    doc.addPage();
  }

  // כותרת לגרף
  doc.font('Times-Bold').fontSize(HEADER_SIZE).fillColor('black');
  doc.text(headerText, legendX, doc.y, { align: 'left' });

  // נקודת התחלה לשניהם
  const yTop = doc.y + GAP_AFTER_HEADER;

  // פונקציה שמציירת "עמוד" אחד: מקרא בעד 2 עמודות + הגרף מימין
  const drawOnePage = (startIndex) => {
    // טווח גובה זמין בעמוד זה
    const availableH = pageH - bottom - yTop;

    // ציור המקרא בשתי עמודות עם מדידת גובה אמיתית לכל פריט (ללא חפיפות)
    doc.font('Times-Roman').fontSize(FONT_SIZE).fillColor('black');

    let col = 0;
    let curX = legendX;
    let curY = yTop;
    const BOX = 9; // ריבוע צבע

    let i = startIndex;
    while (i < legendArray.length) {
      const it = legendArray[i];
      const label = (typeof it === 'string') ? it : (it?.label ?? '');
      let color   = (typeof it === 'object') ? it?.color : null;
      if (color && /^rgb\(/i.test(color)) color = rgbToHex(color);

      // נמדוד גובה טקסט בפועל לרוחב העמודה
      const textWidth = LEGEND_COL_W - (BOX + 6);
      const measuredH = Math.max(
        ROW_MIN,
        doc.heightOfString(` ${label}`, { width: textWidth })
      );
      const itemH = measuredH + ROW_GAP;

      // אם אין מקום לפריט בעמודה זו – עוברים לעמודה הבאה
      if (curY + itemH > yTop + availableH) {
        col += 1;
        if (col >= LEGEND_COLS) break; // אין יותר עמודות — נעצור לעמוד הבא
        curX = legendX + col * LEGEND_COL_W;
        curY = yTop;
        continue; // ננסה שוב באותה אינדקס לאחר מעבר עמודה
      }

      // ציור ריבוע צבע
      if (color) {
        doc.fillColor(color).rect(curX, curY + 3, BOX, BOX).fill();
      }
      // ציור הטקסט (עטיפה לפי רוחב)
      doc.fillColor('black').font('Times-Roman');
      doc.text(` ${label}`, curX + BOX + 4, curY, { width: textWidth });

      curY += itemH;
      i += 1; // עברנו לפריט הבא
    }

    // צייר את הגרף מיושר ל־yTop
    doc.image(imageBuffer, chartX, yTop, { fit: CHART_FIT, align: 'right', valign: 'top' });

    // גובה הבלוק – המקסימום בין המקרא שצויר לבין גובה הגרף
    const legendHeightUsed = Math.max(curY - yTop, 0);
    const blockHeight = Math.max(legendHeightUsed, CHART_H);

    // קידום y אחרי הבלוק
    doc.y = yTop + blockHeight + 12;

    // נחזיר כמה פריטים צרכנו
    return i - startIndex;
  };

  // מציירים עמודים רצופים עד שנגמור את כל המקרא
  let index = 0;
  if (legendArray.length === 0) {
    // אין מקרא? נצייר רק את הגרף
    doc.image(imageBuffer, chartX, yTop, { fit: CHART_FIT, align: 'right', valign: 'top' });
    doc.y = yTop + CHART_H + 12;
    return;
  }

  // העמוד הראשון – כבר בכאן; אם נשאר, נעבור לעמודים נוספים
  let consumed = drawOnePage(index);
  index += consumed;

  while (index < legendArray.length) {
    // עמוד חדש – חזרה על הכותרת כדי לשמור הקשר
    doc.addPage();
    doc.font('Times-Bold').fontSize(HEADER_SIZE).fillColor('black');
    doc.text(headerText, left, top, { align: 'left' });
    // נקודת התחלה לעמוד זה
    const _yTop = doc.y + GAP_AFTER_HEADER;

    // נצייר את עמוד ההמשך
    const availableH2 = pageH - bottom - _yTop;
    // ננצל את אותה פונקציה – אך צריך לגרום לה לצייר מול _yTop
    // פיתרון פשוט: נזיז זמנית את doc.y כדי שהחישובים ישתמשו ב־_yTop
    const oldY = doc.y;
    doc.y = _yTop - GAP_AFTER_HEADER; // כך שתוך הפונקציה yTop יחושב כראוי
    consumed = drawOnePage(index);
    index += consumed;
    // נחזיר את doc.y למצב שכבר הועלה ע"י drawOnePage
  }
}





async function generatePDFReport(gitleaksFindings, config, tools = {}, base64Images = {}) {
  const { trivyFindings = [], banditFindings = [], containerFindings = [] } = tools || {};
  const allFindings = normalizeFindings({ gitleaks: gitleaksFindings, trivy: trivyFindings, bandit: banditFindings, container: containerFindings  });
  const filteredFindings = filterFindings(allFindings, config);

  const workspacePath = config.workspacePath || process.cwd();
  const outputDir = path.join(workspacePath, 'DevSecodeReports');
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const pdfPath = path.join(outputDir, `DevSecode-Report-${timestamp}.pdf`);
  const jsonPath = path.join(outputDir, `DevSecode-Report-${timestamp}.json`);

  const doc = new PDFDocument({ margin: 50 });
  doc.font('Times-Roman'); // ← פונט ברירת מחדל לכל הדוח
  doc.pipe(fs.createWriteStream(pdfPath));

  const sections = [
    { key: 'secrets', title: 'Secret Detection' },
    { key: 'sca', title: 'Software Composition Analysis (SCA)' },
    { key: 'sast', title: 'Static Application Security Testing (SAST)' },
    { key: 'container', title: 'Container Scanning' },
  ];
  // 🟩 גובה העמוד
  const pageHeight = doc.page.height;
  
  // 🟩 מרכז Y של העמוד פחות מחצית מגובה הטקסטים הכולל (נניח 80px)
  const blockHeight = 80;
  const centerY = (pageHeight - blockHeight) / 2;
  
  // 🟦 כותרת ראשית באמצע הדף
  doc
    .font('Times-Bold')
    .fontSize(26)
    .fillColor('black')
    .text('DevSecode Security Report', {
      align: 'center',
      baseline: 'middle',
      lineGap: 10,
      continued: false,
    });
  
  // 🟦 ריווח קטן בין שורות
  doc.moveDown(0.5);
  doc.font('Times-Roman').fontSize(24).text(`Project: ${resolveProjectName(config)}`, { align: 'center' });


  // 🟫 תאריך למטה
  doc
    .fontSize(12)
    .fillColor('gray')
    .text(`Generated on: ${new Date().toLocaleString()}`, 0, pageHeight - 70, {
      align: 'center',
    });
  
  // 🟨 קפיצה ליוזמה (הגדר Y ישירות למרכז הדף)
  doc.y = centerY;
  doc.addPage();

  let isFirstSection = true;

  for (const { key, title } of sections) {
    const typeKey = `${key}_type`;
    const severityKey = `${key}_severity`;
  
    if (base64Images[typeKey]?.image || base64Images[severityKey]?.image) {
      if (!isFirstSection) {
        doc.addPage(); // רק אחרי הפעם הראשונה
      } else {
        isFirstSection = false;
      }
  
      doc.font('Times-Bold').fontSize(18).text(title, { align: 'center' });
      doc.moveDown(0.5);
      renderChartWithLegend(doc, base64Images[typeKey], 'Findings by Type');
      doc.moveDown(0.8);
      renderChartWithLegend(doc, base64Images[severityKey], 'Findings by Severity');
    }
  }

  

  if (filteredFindings.length === 0) {
    doc.fontSize(14).text('No findings matched the selected filters.', { align: 'center' });
  } else {
    filteredFindings.forEach(finding => {
      doc.addPage();
      const { level, color } = getSeverity(finding.Entropy);
      doc.fillColor(color).font('Times-Bold').fontSize(16).text(`Severity: ${level}`);
      doc.moveDown(1);
      doc.fillColor('black').fontSize(12).font('Times-Roman');
      doc.font('Times-Bold').text('Tool: ', { continued: true });
      doc.font('Times-Roman').text(finding.tool); doc.moveDown(0.5);
      doc.font('Times-Bold').text('File: ', { continued: true });
      doc.font('Times-Roman').text(finding.File); doc.moveDown(0.5);
      doc.font('Times-Bold').text('Line: ', { continued: true });
      doc.font('Times-Roman').text(finding.StartLine.toString()); doc.moveDown(0.5);
      doc.font('Times-Bold').text('Rule: ', { continued: true });
      doc.font('Times-Roman').text(finding.RuleID); doc.moveDown(0.5);
      doc.font('Times-Bold').text('Description: ', { continued: true });
      doc.font('Times-Roman').text(finding.Description || 'N/A'); doc.moveDown(0.5);
      if (finding.Match) {
        doc.font('Times-Bold').text('Snippet: ', { continued: true });
        doc.font('Times-Roman').text(finding.Match); doc.moveDown(0.5);
      }
      doc.font('Times-Bold').text('Recommendation: ', { continued: true });
      doc.font('Times-Roman').text(getRecommendation(finding.RuleID));
      doc.moveDown(1.5);
    });
  }

  doc.end();
  await new Promise(resolve => doc.on('finish', resolve));
  fs.writeFileSync(jsonPath, JSON.stringify(filteredFindings, null, 2));
  return pdfPath;
}

module.exports = { generatePDFReport };