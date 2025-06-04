const fsPromises = require("fs/promises");
const path = require("path");

/**
 * Generate JSON report for container scan findings.
 * Produces a single `ContainerScanning_Report.json` file – no Markdown side file.
 */
async function generateContainerReports(imageName, flatFindings, outputDir) {
  const raw = flatFindings._rawImageReport || {};

  // -----------------------------------------------------------------------
  // 1. Image metadata
  // -----------------------------------------------------------------------
  const imageMeta = {
    ArtifactName: raw.ArtifactName || imageName,
    CreatedAt: new Date().toISOString(),
    ImageID: raw.Metadata?.ImageID || raw.ArtifactID || "unknown",
    Digest: raw.Digest || "unknown",
  };

  // -----------------------------------------------------------------------
  // 2. Severity counts and summary line
  // -----------------------------------------------------------------------
   const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const counts = Object.fromEntries(severities.map((s) => [s, 0]));
  flatFindings.forEach((v) => {
    if (counts[v.Severity] !== undefined) counts[v.Severity]++;
  });
  const totalVulns = flatFindings.length;
  const summaryLine = `Total vulnerabilities: ${totalVulns} (CRITICAL: ${counts.CRITICAL}, HIGH: ${counts.HIGH}, MEDIUM: ${counts.MEDIUM}, LOW: ${counts.LOW}, UNKNOWN: ${counts.UNKNOWN})`;

  // -----------------------------------------------------------------------
  // 3. Top vulnerabilities (CRITICAL & HIGH)
  // -----------------------------------------------------------------------
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
      Remediation: v.FixedVersion
        ? `Upgrade ${v.PkgName} to ${v.FixedVersion}`
        : "Rebuild image using a newer base image or patched packages",
    }));

  // 4. Recommendations list (flattened) -----------------------------------
   const recommendations = topVulns.map((v) => ({
    ID: v.ID,
    recommendation: v.Remediation,
  }));

  // -----------------------------------------------------------------------
  // 5. Build JSON object
  // -----------------------------------------------------------------------
  const jsonReport = {
    summary_line: summaryLine,
    metadata: imageMeta,
    vulnerability_summary: counts,
    top_vulnerabilities: topVulns,
    recommendations,
    next_steps:
      "After applying fixes, rerun DevSecode's container scan to ensure vulnerabilities are resolved.",
  };

  // -----------------------------------------------------------------------
  // 6. Persist JSON
  // -----------------------------------------------------------------------
  const safeName = imageName.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const jsonPath = path.join(outputDir, `ContainerScanning_Report.json`);
  await fsPromises.writeFile(jsonPath, JSON.stringify(jsonReport, null, 2));
}

module.exports = { generateContainerReports };
