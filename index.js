const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");

const reportPath = core.getInput("trivy-report");

if (!reportPath) {
    core.setFailed("Report path is required");
    process.exit(1);
}

fs.readFile(reportPath, "utf8", async (err, data) => {
    if (err) {
        core.setFailed(`Error reading the report: ${err.message}`);
        process.exit(1);
    }

    try {
        const report = JSON.parse(data);
        const results = report.Results;

        results.forEach(result => {
            core.info(`Target: ${result.Target}`);
            core.info(`Class: ${result.Class}`);
            core.info(`Type: ${result.Type}`);

            if (result.Vulnerabilities) {
                result.Vulnerabilities.forEach(vuln => {
                    core.info(`  VulnerabilityID: ${vuln.VulnerabilityID}`);
                    core.info(`  PkgName: ${vuln.PkgName}`);
                    core.info(`  InstalledVersion: ${vuln.InstalledVersion}`);
                    core.info(`  FixedVersion: ${vuln.FixedVersion}`);
                    core.info(`  Severity: ${vuln.Severity}`);
                    core.info(`  Title: ${vuln.Title}`);
                    core.info(`  Description: ${vuln.Description}`);
                    core.info(`  PrimaryURL: ${vuln.PrimaryURL}`);
                    core.info("---------------------------------");
                });
            }
        });

        // Log per verificare l'ArtifactName e altri dettagli
        core.info(`ArtifactName: ${report.ArtifactName}`);
        const [fullRegistry, repoTag] = report.ArtifactName.split("/");
        const [repository] = repoTag.split(":");

        core.info(`Full Registry: ${fullRegistry}`);
        core.info(`Repo Tag: ${repoTag}`);
        core.info(`Repository: ${repository}`);

        // Usa il namespace corretto
        const namespace = "carlo02sorre"; 

        // Corretto URL per recuperare i tag
        const url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags`;
        core.info(`Fetching tags from: ${url}`);

        try {
            const response = await axios.get(url);
            const tags = response.data.results;

            core.info("Tags:");
            tags.forEach(tag => {
                core.info(`  Tag: ${tag.name}, Is Current: ${tag.is_current}`);
            });
        } catch (apiErr) {
            core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
            process.exit(1);
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
