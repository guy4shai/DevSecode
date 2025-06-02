function getFixedVersionFromOSV(packageName, version) {
  const https = require("https");

  const data = JSON.stringify({
    version: version,
    package: {
      name: packageName,
      ecosystem: "PyPI"
    }
  });

  const options = {
    hostname: "api.osv.dev",
    port: 443,
    path: "/v1/query",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": data.length
    }
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.vulns && parsed.vulns.length > 0) {
            const fixes = parsed.vulns.flatMap(vuln =>
              vuln.affected?.flatMap(a =>
                a.ranges?.flatMap(r =>
                  r.events?.map(e => e.fixed).filter(Boolean)
                )
              ).filter(Boolean) || []
            );
            resolve(fixes.length > 0 ? fixes : null);
          } else {
            resolve(null);
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on("error", (err) => reject(err));
    req.write(data);
    req.end();
  });
}

module.exports = {
  getFixedVersionFromOSV,
};
