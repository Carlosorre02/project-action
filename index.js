const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const semver = require('semver');
const { execSync } = require('child_process');

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
        const artifactName = report.ArtifactName;

        if (!artifactName) {
            core.setFailed("ArtifactName is undefined or missing in the report.");
            process.exit(1);
        }

        core.info(`Base Image: ${artifactName}`);

        const extractVulnInfo = (vulnerabilities) => {
            return vulnerabilities.map(vuln => {
                return {
                    Target: vuln.Target,
                    PkgName: vuln.PkgName,
                    VulnerabilityID: vuln.VulnerabilityID,
                    Severity: vuln.Severity,
                    InstalledVersion: vuln.InstalledVersion,
                    FixedVersion: vuln.FixedVersion || "No fix available",
                };
            });
        };

        report.Results.forEach(result => {
            core.info(`Target: ${result.Target}`);
            const relevantVulns = extractVulnInfo(result.Vulnerabilities || []);

            relevantVulns.forEach(vulnInfo => {
                core.info(`Package: ${vulnInfo.PkgName}`);
                core.info(`Vulnerability ID: ${vulnInfo.VulnerabilityID}`);
                core.info(`Severity: ${vulnInfo.Severity}`);
                core.info(`Installed Version: ${vulnInfo.InstalledVersion}`);
                core.info(`Fixed Version: ${vulnInfo.FixedVersion}`);
                core.info("---");
            });
        });

        const parts = artifactName.split(":")[0].split("/");

        let namespace = "library";
        let repository = parts[0];

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);

        const getAlpineTags = async (namespace, repository, currentTag) => {
            let url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags/?name=alpine&page_size=100`;
            let tags = [];

            while (url) {
                try {
                    const response = await axios.get(url);
                    const pageTags = response.data.results;

                    if (!pageTags.length) {
                        core.setFailed("No tags found for the specified repository.");
                        process.exit(1);
                    }

                    const currentVersion = currentTag.split(":")[1].split("-alpine")[0];

                    pageTags.forEach(tag => {
                        const tagVersion = tag.name.split("-alpine")[0];

                        if (tag.name.includes("alpine") && semver.valid(tagVersion) && semver.gt(tagVersion, currentVersion)) {
                            tags.push(tag.name);
                        }
                    });

                    url = response.data.next;
                } catch (apiErr) {
                    core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
                    process.exit(1);
                }
            }

            return tags;
        };

        const currentTag = artifactName;
        const alpineTags = await getAlpineTags(namespace, repository, currentTag);

        const sortTags = (tags) => {
            return tags.sort((a, b) => {
                const [versionA, alpineA] = a.split("-alpine");
                const [versionB, alpineB] = b.split("-alpine");

                const semverCompare = semver.compare(versionA, versionB);
                if (semverCompare !== 0) return semverCompare;

                const alpineVersionA = alpineA ? alpineA.replace('.', '') : '';
                const alpineVersionB = alpineB ? alpineB.replace('.', '') : '';

                return alpineVersionA.localeCompare(alpineVersionB, undefined, { numeric: true });
            });
        };

        if (alpineTags.length > 0) {
            const sortedTags = sortTags(alpineTags);

            core.info("Alpine Tags ordinati:");
            sortedTags.forEach(tag => core.info(`  Tag: ${tag}`));

            // Esegui la scansione Trivy solo sui primi 5 tag
            const topFiveTags = sortedTags.slice(0, 5); // Prendi i primi 5 tag

            for (const tag of topFiveTags) {
                try {
                    core.info(`Eseguo la scansione Trivy per l'immagine: ${tag}`);
                    execSync(`trivy image --severity CRITICAL,HIGH ${tag} --format json --output trivy-report-${tag}.json`);
                    core.info(`Scansione completata per ${tag}`);
                } catch (error) {
                    core.setFailed(`Errore durante la scansione di ${tag}: ${error.message}`);
                }
            }
        } else {
            core.info("Non sono stati trovati tag Alpine più recenti.");
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
