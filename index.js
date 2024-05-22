const fs = require("fs");
const core = require("@actions/core");

const reportPath = core.getInput("trivy-report");

if (!reportPath) {
    core.setFailed("Report path is required2");
    process.exit(1);
}

fs.readFile(reportPath, "utf8", (err, data) => {
    if (err) {
        core.setFailed(`Error reading the report: ${err.message}`);
        process.exit(1);
    }

    try {
        const report = JSON.parse(data);
        const results = report.Results;

        results.forEach(result => {
            core.info("Target: ${result.Target}");
            core.info("Class: ${result.Class}");
            core.info("Type: ${result.Type}");

            if (result.Vulnerabilities) {
                result.Vulnerabilities.forEach(vuln => {
                    core.info("  VulnerabilityID: ${vuln.VulnerabilityID}");
                    core.info("  PkgName: ${vuln.PkgName}");
                    core.info("  InstalledVersion: ${vuln.InstalledVersion}");
                    core.info("  FixedVersion: ${vuln.FixedVersion}");
                    core.info("  Severity: ${vuln.Severity}");
                    core.info("  Title: ${vuln.Title}");
                    core.info("  Description: ${vuln.Description}");
                    core.info("  PrimaryURL: ${vuln.PrimaryURL}");
                    core.info("---------------------------------");
                });
            }
        });
    } catch (parseErr) {
        core.setFailed("Error parsing the report: ${parseErr.message}");
        process.exit(1);
    }
});

