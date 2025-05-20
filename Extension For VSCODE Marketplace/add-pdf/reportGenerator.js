const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');

function getSeverity(entropy) {
  if (entropy > 4.5) return { level: 'Critical', color: '#B33A3A' };
  if (entropy > 4.0) return { level: 'High', color: '#FF6F61' };
  if (entropy > 3.5) return { level: 'Medium', color: 'FFB347' };
  return { level: 'Low', color: 'FFF176' };
}


function getRecommendation(ruleID) {
  return `It is recommended to review uses of '${ruleID}', follow secure coding practices, and replace any exposed secrets with secure storage methods.`;
}

function getSeverityScore(level) {
  return { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 }[level] ?? 4;
}


function normalizeFindings({ gitleaks = [], trivy = [], semgrep = [], bandit = [] }) {
  const normalized = [];

  // Gitleaks
  gitleaks.forEach(f => {
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

  // Trivy
  trivy.Results?.forEach(result => {
    result.Vulnerabilities?.forEach(vuln => {
      normalized.push({
        tool: 'Trivy',
        File: result.Target || vuln.PkgName,
        StartLine: 1,
        RuleID: vuln.VulnerabilityID,
        Description: vuln.Title,
        Match: vuln.PkgName,
        Entropy: getEntropyFromSeverity(vuln.Severity)
      });
    });
  });

  // Semgrep
  semgrep.results?.forEach(item => {
    normalized.push({
      tool: 'Semgrep',
      File: item.path,
      StartLine: item.start?.line || 1,
      RuleID: item.check_id,
      Description: item.extra?.message || item.message,
      Match: '', // אין match מדויק
      Entropy: 4.5 // נניח חומרה בינונית כברירת מחדל
    });
  });

  // Bandit
  bandit.results?.forEach(item => {
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

  return normalized;
}

function getEntropyFromSeverity(sev) {
  switch (sev.toLowerCase?.()) {
    case 'critical': return 5.0;
    case 'high': return 4.5;
    case 'medium': return 4.0;
    case 'low': return 3.0;
    default: return 1.0;
  }
}

function filterFindings(findings, config) {
  const selectedSeverities = config.selectedSeverities || ['Critical','High', 'Medium', 'Low'];

  const filtered = findings.filter(finding => {
    const sev = getSeverity(finding.Entropy).level;
    return selectedSeverities.includes(sev);
  });

  if (config.sortBy === 'severity') {
    filtered.sort((a, b) => {
      const aScore = getSeverityScore(getSeverity(a.Entropy).level);
      const bScore = getSeverityScore(getSeverity(b.Entropy).level);
      return aScore - bScore;
    });
  } else if (config.sortBy === 'line') {
    filtered.sort((a, b) => (a.StartLine || 0) - (b.StartLine || 0));
  }

  return filtered;
}

async function generatePDFReport(gitleaksFindings, config, tools = {}) {
  const { trivyFindings = [], semgrepFindings = [], banditFindings = [] } = tools;

  const allFindings = normalizeFindings({
    gitleaks: gitleaksFindings,
    trivy: trivyFindings,
    semgrep: semgrepFindings,
    bandit: banditFindings
  });

  const filteredFindings = filterFindings(allFindings, config);

  const workspacePath = config.workspacePath || process.cwd();
  const outputDir = path.join(workspacePath, 'DevSecodeReports');
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const pdfPath = path.join(outputDir, `DevSecode-Report-${timestamp}.pdf`);
  const jsonPath = path.join(outputDir, `DevSecode-Report-${timestamp}.json`);

  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(fs.createWriteStream(pdfPath));

  const now = new Date().toLocaleString();
  doc.fontSize(10).fillColor('gray').text(`Generated on: ${now}`, { align: 'right' });
  doc.moveDown();

  doc.font('Courier-Bold').fontSize(20).fillColor('black').text('DevSecode Report', { align: 'center' });
  doc.moveDown();

  if (filteredFindings.length === 0) {
    doc.fontSize(14).text('No findings matched the selected filters.', { align: 'center' });
  } else {
    filteredFindings.forEach(finding => {
      if (doc.y > doc.page.height - 150) {
        doc.addPage();
      }

      const { level, color } = getSeverity(finding.Entropy);

      doc.fillColor(color).font('Courier-Bold').fontSize(16).text(`Severity: ${level}`);
      doc.fillColor('black').fontSize(12).font('Courier');

      doc.font('Courier-Bold').text('Tool: ', { continued: true });
      doc.font('Courier').text(finding.tool);
      doc.moveDown(0.5);

      doc.font('Courier-Bold').text('File: ', { continued: true });
      doc.font('Courier').text(finding.File);
      doc.moveDown(0.5);

      doc.font('Courier-Bold').text('Line: ', { continued: true });
      doc.font('Courier').text(finding.StartLine.toString());
      doc.moveDown(0.5);

      doc.font('Courier-Bold').text('Rule: ', { continued: true });
      doc.font('Courier').text(finding.RuleID);
      doc.moveDown(0.5);

      doc.font('Courier-Bold').text('Description: ', { continued: true });
      doc.font('Courier').text(finding.Description || 'N/A');
      doc.moveDown(0.5);

      if (finding.Match) {
        doc.font('Courier-Bold').text('Snippet: ', { continued: true });
        doc.font('Courier').text(finding.Match);
        doc.moveDown(0.5);
      }

      doc.font('Courier-Bold').text('Recommendation: ', { continued: true });
      doc.font('Courier').text(getRecommendation(finding.RuleID));
      doc.moveDown(1.5);
    });
  }

  doc.end();
  await new Promise(resolve => doc.on('finish', resolve));
  fs.writeFileSync(jsonPath, JSON.stringify(filteredFindings, null, 2));
  return pdfPath;
}

module.exports = { generatePDFReport };
