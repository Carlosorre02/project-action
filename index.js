const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const semver = require("semver");
const { exec } = require("child_process");
const artifact = require("@actions/artifact");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const reportPath = core.getInput("trivy-report");

if (!reportPath) {
    core.setFailed("Report path is required");
    process.exit(1);
}

let summaryReport = {
    baseImage: "",
    severity: "LOW, MEDIUM, HIGH, CRITICAL",
    iterationCount: 0,
    versionSelectionLogic: "Le versioni successive sono ordinate in base alla versione semantica, dalla più vecchia alla più recente (crescente).",
    imagesAnalyzed: [],
};

const extractCveBySeverity = (vulnerabilities) => {
    const cveBySeverity = { LOW: [], MEDIUM: [], HIGH: [], CRITICAL: [] };
    vulnerabilities.forEach((vuln) => {
        if (vuln.VulnerabilityID) {
            cveBySeverity[vuln.Severity.toUpperCase()].push(vuln.VulnerabilityID);
        }
    });
    return cveBySeverity;
};

const processCve = (results, target) => {
    const vulnerabilities = results.Vulnerabilities || [];
    const cveBySeverity = extractCveBySeverity(vulnerabilities);
    return { target, vulnerabilities: cveBySeverity };
};

const trivyScan = async (image, reportFileName) => {
    const fullImageName = `${image}`;
    return new Promise((resolve, reject) => {
        exec(
            `trivy image --format json --output ${reportFileName} --severity LOW,MEDIUM,HIGH,CRITICAL ${fullImageName}`,
            (error, stdout, stderr) => {
                if (error) {
                    reject(`Errore durante la scansione di Trivy per l'immagine ${fullImageName}: ${stderr}`);
                } else {
                    resolve(`Trivy report per ${fullImageName} salvato.`);
                }
            }
        );
    });
};

const uploadArtifactForImage = async (reportFileName) => {
    try {
        const artifactClient = artifact.create();
        await artifactClient.uploadArtifact(reportFileName, [reportFileName], '.');
        const repositoryEnv = process.env.GITHUB_REPOSITORY;
        const runId = process.env.GITHUB_RUN_ID;
        const reportLink = `https://github.com/${repositoryEnv}/actions/runs/${runId}/artifacts`;
        core.info(`Upload Trivy JSON Report for ${reportFileName}: ${reportLink}`);
    } catch (err) {
        core.setFailed(`Errore nel caricamento del report per l'immagine ${reportFileName}: ${err}`);
    }
};

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

        summaryReport.baseImage = artifactName;
        core.info(`Base Image: ${artifactName}`);

        const baseVersion = artifactName.split(":")[1] || "";
        const baseMajorVersion = semver.major(baseVersion);

        report.Results.forEach((result) => {
            if (result.Target) {
                core.info(`Target: ${result.Target}`);
                const relevantVulns = result.Vulnerabilities || [];

                relevantVulns.forEach((vuln) => {
                    core.info(`Package: ${vuln.PkgName}`);
                    core.info(`Vulnerability ID: ${vuln.VulnerabilityID}`);
                    core.info(`Severity: ${vuln.Severity}`);
                    core.info(`Installed Version: ${vuln.InstalledVersion}`);
                    core.info(`Fixed Version: ${vuln.FixedVersion || "No fix available"}`);
                    core.info("---");
                });

                if (relevantVulns.length === 0) {
                    core.info(`Nessuna vulnerabilità trovata per ${result.Target}`);
                }

                const processedCve = processCve(result, result.Target);
                summaryReport.imagesAnalyzed.push(processedCve);
            }
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

        const getTags = async (namespace, repository, currentTag) => {
            let url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags/?page_size=100`;
            let tags = [];

            while (url) {
                try {
                    const response = await axios.get(url);
                    const pageTags = response.data.results;

                    if (!pageTags.length) {
                        core.setFailed("No tags found for the specified repository.");
                        process.exit(1);
                    }

                    const currentVersion = currentTag.split(":")[1];

                    pageTags.forEach((tag) => {
                        const tagVersion = tag.name;
                        if (semver.valid(tagVersion) && semver.major(tagVersion) === baseMajorVersion && semver.gt(tagVersion, currentVersion)) {
                            tags.push(tag.name);
                        }
                    });

                    url = response.data.next;
                } catch (apiErr) {
                    core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
                    process.exit(1);
                }
            }

            return sortTags(tags);
        };

        const sortTags = (tags) => {
            return tags.sort((a, b) => {
                if (semver.valid(a) && semver.valid(b)) {
                    return semver.compare(a, b);
                }
                return 0;
            });
        };

        const currentTag = artifactName;
        const availableTags = await getTags(namespace, repository, currentTag);

        if (availableTags.length > 0) {
            const sortedTags = sortTags(availableTags);
            core.info("Tag disponibili ordinati:");
            sortedTags.forEach((tag) => core.info(`  Tag: ${tag}`));

            const top5Images = sortedTags.slice(0, 5);

            for (const image of top5Images) {
                core.info(`Inizio scansione per immagine: ${image}`);
                const reportFileName = `trivy-report-${image}.json`;

                try {
                    await trivyScan(image, reportFileName);
                    await uploadArtifactForImage(reportFileName);
                    await sleep(2000);
                } catch (err) {
                    core.setFailed(`Errore nella scansione di ${image}: ${err}`);
                }
            }

            summaryReport.iterationCount = top5Images.length;
            fs.writeFileSync("summary-report.json", JSON.stringify(summaryReport, null, 2));
            core.info("Summary report generated successfully!");

            const artifactClient = artifact.create();
            await artifactClient.uploadArtifact("summary-report.json", ["summary-report.json"], ".");
        } else {
            core.info("Non sono stati trovati tag più recenti.");
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
