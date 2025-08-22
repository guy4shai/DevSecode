const fs = require("fs");
const path = require("path");
const util = require("util");
const cp = require("child_process");
const exec = util.promisify(cp.exec);
const os = require("os");

/**
 * Generate a JSON report object for a single image scan (no file I/O here).
 */
async function generateContainerReport(imageName, flatFindings) {
  const raw = flatFindings._rawImageReport || {};

  // 1. Metadata
  const imageMeta = {
    ArtifactName: raw.ArtifactName || imageName,
    CreatedAt: new Date().toISOString(),
    ImageID: raw.Metadata?.ImageID || raw.ArtifactID || "unknown",
    Digest: raw.Digest || "unknown",
  };

  // 2. Severity counts & summary
  const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const counts = Object.fromEntries(severities.map(s => [s, 0]));
  flatFindings.forEach(v => { if (counts[v.Severity] !== undefined) counts[v.Severity]++; });
  const summaryLine = `Total vulnerabilities: ${flatFindings.length} (` +
    severities.map(s => `${s}: ${counts[s]}`).join(", ") + ")";

  // 3. Top vulnerabilities (CRITICAL/HIGH)
  const topVulns = flatFindings
    .filter(v => ["CRITICAL", "HIGH"].includes(v.Severity))
    .sort((a, b) => {
      const rank = { CRITICAL: 0, HIGH: 1 };
      if (rank[a.Severity] !== rank[b.Severity]) return rank[a.Severity] - rank[b.Severity];
      const scoreA = a.CVSS?.nvd?.V3Score || a.CVSSScore || 0;
      const scoreB = b.CVSS?.nvd?.V3Score || b.CVSSScore || 0;
      return scoreB - scoreA;
    })
    .map(v => ({
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
      Remediation: v.FixedVersion
        ? `Upgrade ${v.PkgName} to ${v.FixedVersion}`
        : `Rebuild image using patched base image`,
    }));

  // 4. Recommendations
  const recommendations = topVulns.map(v => ({ ID: v.ID, recommendation: v.Remediation }));

  return {
    summary_line: summaryLine,
    metadata: imageMeta,
    vulnerability_summary: counts,
    top_vulnerabilities: topVulns,
    recommendations,
    next_steps: "After applying fixes, rerun DevSecode container scan to verify remediation.",
  };
}

/**
 * Run a Trivy image scan and collect raw findings, then cleanup intermediate file
 */
async function runContainerScan(imageName, trivyConfigPath, workspacePath) {
  const safe = imageName.replace(/[^a-zA-Z0-9_.-]/g, "_");
  // Write intermediate JSON to OS temp directory instead of workspace
  const tmpDir = os.tmpdir();
  const outPath = path.join(tmpDir, `trivy_image_${safe}.json`);
  const cmd = trivyConfigPath
    ? `trivy image "${imageName}" --config "${trivyConfigPath}" --format json --output "${outPath}"`
    : `trivy image "${imageName}" --format json --output "${outPath}"`;

  await exec(cmd, { maxBuffer: 1024 * 1000 });

  // Load and flatten findings
  const raw = JSON.parse(fs.readFileSync(outPath, 'utf8'));
  const flat = raw.Results?.flatMap(r => r.Vulnerabilities || []) || [];
  flat._rawImageReport = raw;

  // Remove intermediate file
  try { fs.unlinkSync(outPath); } catch (e) { /* ignore */ }

  return flat;
}

/**
 * High-level: scan one image and build its report object
 */
async function runFullContainerScan(imageName, workspacePath, trivyConfigPath) {
  const flat = await runContainerScan(imageName, trivyConfigPath, workspacePath);
  return generateContainerReport(imageName, flat);
}

module.exports = { runFullContainerScan };

