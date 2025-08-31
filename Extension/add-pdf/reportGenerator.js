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

function renderChartWithLegend(doc, chartData, titleText, fixedY = null) {
  let entry = null;
  if (typeof chartData === 'string') {
    entry = { image: chartData, legend: [] };
  } else if (chartData && chartData.image) {
    entry = { image: chartData.image, legend: chartData.legend || [] };
  } else if (chartData && chartData.dataUrl) {
    entry = { image: chartData.dataUrl, legend: chartData.legend || [] };
  }

  if (!entry || !entry.image) return;

  const imageBuffer = Buffer.from(chartData.image.replace(/^data:image\/png;base64,/, ''), 'base64');
  const chartX = 300;
  const chartY = fixedY !== null ? fixedY : doc.y;
  const chartWidth = 250;
  const chartHeight = 250;

  doc.image(imageBuffer, chartX, chartY, { fit: [chartWidth, chartHeight] });

  const legendItems = chartData.legend || [];
  const legendX = 50;
  let legendY = chartY;

  doc.fillColor('black');
  doc.font('Times-Bold').fontSize(14).text(titleText, legendX, legendY, { underline: false });
  legendY += 25;

  legendItems.forEach(({ label, color }) => {
    if (color && color.startsWith("rgb")) {
      color = rgbToHex(color);
    }

    const boxSize = 10;
    doc.fillColor(color).rect(legendX, legendY, boxSize, boxSize).fill();
    doc.fillColor('black').font('Times-Bold').fontSize(12).text(` ${label}`, legendX + boxSize + 5, legendY - 1);
    legendY += 20;
  });

  doc.moveDown(2);
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
      renderChartWithLegend(doc, base64Images[typeKey], 'Findings by Type:', 100);
      renderChartWithLegend(doc, base64Images[severityKey], 'Findings by Severity:', 420);
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