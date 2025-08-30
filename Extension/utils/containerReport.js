const fs = require("fs");
const path = require("path");
const util = require("util");
const cp = require("child_process");
const exec = util.promisify(cp.exec);
const os = require("os");

// --- helpers for Dockerfile mapping ---
function findDockerfiles(rootPath) {
  const found = [];
  (function walk(dir) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (['.git', 'node_modules', 'dist', 'out', 'build', '.venv', 'venv'].includes(e.name)) continue;
        walk(p);
      } else if (e.isFile() && /(^Dockerfile$|\.dockerfile$)/i.test(e.name)) {
        found.push(p);
      }
    }
  })(rootPath);
  return found;
}

function extractFromRefs(dockerfilePath, workspaceRoot) {
  const lines = fs.readFileSync(dockerfilePath, 'utf8').split(/\r?\n/);
  const refs = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*FROM\s+([^\s]+)(?:\s+AS\s+\S+)?\s*$/i);
    if (m) {
      const full = m[1];                    // e.g., nginx:1.25-alpine@sha256:..., node:20-alpine
      const noDigest = full.split('@')[0];
      const [nameOnly, tag] = noDigest.split(':');
      refs.push({
        imageName: nameOnly,                // 'nginx' / 'gcr.io/foo/bar'
        tag: tag || null,                   // '1.25-alpine'
        file_path: path.resolve(dockerfilePath),
        line_number: i + 1,
      });
    }
  }
  return refs;
}

function normalizeImageName(s) { return (s || '').split('@')[0].split(':')[0]; }
function findRefForArtifact(artifactName, refs) {
  const norm = normalizeImageName(artifactName);
  const tag = (artifactName.split('@')[0].split(':')[1]) || null;
  // קודם חיפוש התאמה מלאה (שם + תג), אם אין — לפי שם בלבד
  return refs.find(r => r.imageName === norm && r.tag === tag)
    || refs.find(r => r.imageName === norm)
    || null;
}

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
      file_path: v.file_path || null,
      line_number: v.line_number || null,
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
  // --- enrich flat findings with file_path & line_number from Dockerfile ---
  try {
    const dockerfiles = findDockerfiles(workspacePath);
    const refs = dockerfiles.flatMap(df => extractFromRefs(df, workspacePath));
    const artifact = flat._rawImageReport?.ArtifactName || imageName;
    const match = findRefForArtifact(artifact, refs);
    if (match) {
      flat.forEach(v => {
        if (v && typeof v === 'object') {
          v.file_path = path.resolve(match.file_path);
          v.line_number = match.line_number;
        }
      });
    }
  } catch (_) { }

  return generateContainerReport(imageName, flat);
}

module.exports = { runFullContainerScan };
