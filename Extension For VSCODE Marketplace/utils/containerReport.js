const fsPromises = require("fs/promises");
const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");
const util = require("util");
const execAsync = util.promisify(exec);

// Generate JSON report for container scan findings.
// Produces a single `ContainerScanning_Report.json` file – no Markdown side file.

async function generateContainerReports(
  imageName,
  flatFindings,
  outputDir,
  rootPath
) {
  const raw = flatFindings._rawImageReport || {};

  // Image metadata
  const imageMeta = {
    ArtifactName: raw.ArtifactName || imageName,
    CreatedAt: new Date().toISOString(),
    ImageID: raw.Metadata?.ImageID || raw.ArtifactID || "unknown",
    Digest: raw.Digest || "unknown",
  };

  // Severity counts and summary line
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const counts = Object.fromEntries(severities.map((s) => [s, 0]));
  flatFindings.forEach((v) => {
    if (counts[v.Severity] !== undefined) counts[v.Severity]++;
  });

  const imageLocation = await findImageInFiles(rootPath, imageName);
  flatFindings.forEach((vuln) => {
    vuln.file_path = imageLocation.filePath;
    vuln.line_number = imageLocation.lineNumber;
  });
  const totalVulns = flatFindings.length;
  const summaryLine = `Total vulnerabilities: ${totalVulns} (CRITICAL: ${counts.CRITICAL}, HIGH: ${counts.HIGH}, MEDIUM: ${counts.MEDIUM}, LOW: ${counts.LOW}, UNKNOWN: ${counts.UNKNOWN})`;

  // Top vulnerabilities (CRITICAL & HIGH)
  const topVulns = flatFindings
    .filter((v) => v.Severity === "CRITICAL" || v.Severity === "HIGH")
    .sort((a, b) => {
      const rank = { CRITICAL: 0, HIGH: 1 };
      if (rank[a.Severity] !== rank[b.Severity])
        return rank[a.Severity] - rank[b.Severity];
      const sA = a.CVSS?.nvd?.V3Score || a.CVSSScore || 0;
      const sB = b.CVSS?.nvd?.V3Score || b.CVSSScore || 0;
      return sB - sA;
    })
    .map((v) => ({
      ID: v.VulnerabilityID,
      Title: v.Title || v.VulnerabilityID,
      Severity: v.Severity,
      Package: v.PkgName,
      InstalledVersion: v.InstalledVersion,
      FixedVersion: v.FixedVersion || null,
      Description: v.Description || "",
      CVSSv3Score: v.CVSS?.nvd?.V3Score || v.CVSSScore || null,
      CVSSv3Vector: v.CVSS?.nvd?.V3Vector || "",
      References: v.References || [],
      file_path: v.file_path || "unknown",
      line_number: v.line_number || null,
      Remediation: v.FixedVersion
        ? `Upgrade ${v.PkgName} to ${v.FixedVersion}`
        : "Rebuild image using a newer base image or patched packages",
    }));

  // Recommendations list (flattened)
  const recommendations = topVulns.map((v) => ({
    ID: v.ID,
    recommendation: v.Remediation,
  }));

  // Build JSON object
  const jsonReport = {
    summary_line: summaryLine,
    metadata: imageMeta,
    vulnerability_summary: counts,
    top_vulnerabilities: topVulns,
    recommendations,
    next_steps:
      "After applying fixes, rerun DevSecode's container scan to ensure vulnerabilities are resolved.",
  };

  // Persist JSON
  const safeName = imageName.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const jsonPath = path.join(outputDir, `ContainerScanning_Report.json`);
  await fsPromises.writeFile(jsonPath, JSON.stringify(jsonReport, null, 2));
}

function attachFilePathToTrivyFindings(trivyReportPath) {
  const fs = require("fs");

  try {
    const raw = fs.readFileSync(trivyReportPath, "utf-8");
    const json = JSON.parse(raw);

    if (json.Results) {
      json.Results.forEach((result) => {
        const targetFile = result.Target;
        if (result.Vulnerabilities) {
          result.Vulnerabilities.forEach((vuln) => {
            vuln.file_path = targetFile;
          });
        }
      });
    }

    fs.writeFileSync(trivyReportPath, JSON.stringify(json, null, 2));
    console.log("✅ file_path added successfully to each vulnerability.");
  } catch (err) {
    console.error("❌ Failed to process Trivy report:", err);
  }
}

function attachLinesToTrivy(trivyReportPath, dockerfilePath) {
  if (!fs.existsSync(trivyReportPath) || !fs.existsSync(dockerfilePath)) {
    console.warn("Trivy report or Dockerfile not found.");
    return;
  }

  const report = JSON.parse(fs.readFileSync(trivyReportPath, "utf8"));
  const lines = fs.readFileSync(dockerfilePath, "utf8").split("\n");

  const lineMap = {};
  lines.forEach((line, idx) => {
    const pkg = line.split("==")[0].trim().toLowerCase();
    if (pkg) {
      lineMap[pkg] = idx + 1;
    }
  });

  for (const result of report.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      const pkg = vuln.PkgName?.toLowerCase();
      if (pkg && lineMap[pkg]) {
        vuln.line_number = lineMap[pkg];
      }
    }
  }

  fs.writeFileSync(trivyReportPath, JSON.stringify(report, null, 2));
  console.log("✅ Line numbers added to Trivy report.");
}

async function runFullContainerScan(
  imageName,
  rootPath,
  trivyConfigPath,
  dockerfilePath
) {
  const trivyReportPath = path.join(rootPath, "trivy_report.json");

  // 1. Run Trivy
  const trivyCommand = trivyConfigPath
    ? `trivy fs "${rootPath}" --config "${trivyConfigPath}" --format json --output "${trivyReportPath}"`
    : `trivy fs "${rootPath}" --format json --output "${trivyReportPath}"`;

  try {
    await execAsync(trivyCommand);
    console.log("✅ Trivy scan completed.");
  } catch (err) {
    console.error("❌ Trivy scan failed:", err);
    return;
  }

  // 2. Add file_path
  attachFilePathToTrivyFindings(trivyReportPath);

  // 3. Add line_number
  attachLinesToTrivy(trivyReportPath, dockerfilePath);

  // 4. Parse updated Trivy report
  const updatedReport = JSON.parse(fs.readFileSync(trivyReportPath, "utf-8"));
  const flatFindings = [];

  for (const result of updatedReport.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      vuln.file_path = vuln.file_path || result.Target || "unknown";
      flatFindings.push(vuln);
    }
  }

  // 5. Generate final report
  await generateContainerReports(imageName, flatFindings, rootPath, rootPath);
}

async function findImageInFiles(rootDir, imageName) {
  const dockerfilePath = path.join(rootDir, "Dockerfile");

  if (!fs.existsSync(dockerfilePath)) {
    console.warn("⚠ Dockerfile not found.");
    return { filePath: "unknown", lineNumber: null };
  }

  const content = await fsPromises.readFile(dockerfilePath, "utf8");
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const pattern = new RegExp(
      `\\b(FROM|image:)\\s+["']?${imageName}["']?`,
      "i"
    );
    if (pattern.test(line)) {
      return { filePath: dockerfilePath, lineNumber: i + 1 };
    }
  }

  return { filePath: dockerfilePath, lineNumber: null }; // found file but not the image
}

module.exports = {
  generateContainerReports,
  runFullContainerScan,
};
