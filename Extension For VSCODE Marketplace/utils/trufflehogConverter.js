// utils/trufflehogConverter.js
const fs = require("fs");

function convertTrufflehogToGitleaksFormat(inputPath) {
  const rawLines = fs.readFileSync(inputPath, "utf-8").split("\n").filter(Boolean);

  return rawLines
    .map((line) => {
      try {
        const json = JSON.parse(line);
        const filePath = json.SourceMetadata?.Data?.Filesystem?.file || "unknown_file";
        const lineNumber = json.SourceMetadata?.Data?.Filesystem?.line || 1;
        const ruleId = json.DetectorName || "UnknownRule";
        const secret = json.Raw || "REDACTED";
        const description = json.DetectorDescription || "Secret detected by TruffleHog";

        return {
          RuleID: ruleId,
          File: filePath,
          StartLine: lineNumber,
          EndLine: lineNumber,
          Secret: secret,
          Match: secret,
          Description: description,
          Entropy: 5.0, // כדי שיופיע כ-Critical
          redacted: true,
        };
      } catch (e) {
        console.warn("❌ Failed to parse line:", e);
        return null;
      }
    })
    .filter(Boolean);
}

module.exports = { convertTrufflehogToGitleaksFormat };
