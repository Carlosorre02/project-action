const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const semver = require("semver");
const { exec } = require("child_process");
const artifact = require("@actions/artifact");

// Funzione per aggiungere un ritardo
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const reportPath = core.getInput("trivy-report");

if (!reportPath) {
    core.setFailed("Report path is required");
    process.exit(1);
}

// Aggiungi la struttura del report riassuntivo
let summaryReport = {
    baseImage: "",
    severity: "LOW, MEDIUM, HIGH, CRITICAL", // La severity utilizzata
    iterationCount: 0,
    versionSelectionLogic: "La priorità è stata data prima alle patch version, poi alle minor e infine alle major version.",
    imagesAnalyzed: [], // Dettagli sulle immagini analizzate
};

// Funzione per estrarre le informazioni delle vulnerabilità separate per gravità
const extractVulnInfoBySeverity = (vulnerabilities) => {
    const vulnBySeverity = { LOW: [], MEDIUM: [], HIGH: [], CRITICAL: [] };

    vulnerabilities.forEach((vuln) => {
        if (vuln.VulnerabilityID) {
            vulnBySeverity[vuln.Severity.toUpperCase()].push({
                VulnerabilityID: vuln.VulnerabilityID,
            });
        }
    });

    return vulnBySeverity;
};

// Funzione per iterare attraverso i risultati e separare le vulnerabilità per gravità
const processVulnerabilities = (results, target) => {
    const vulnerabilities = results.Vulnerabilities || [];
    const vulnBySeverity = extractVulnInfoBySeverity(vulnerabilities);

    return {
        target,
        vulnerabilities: vulnBySeverity,
    };
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

        // Imposta l'immagine base nel report riassuntivo
        summaryReport.baseImage = artifactName;
        core.info(`Base Image: ${artifactName}`);

        // Iterare attraverso i risultati del report per l'immagine base
        report.Results.forEach((result) => {
            if (result.Target && result.Target !== "Node.js") {
                core.info(`Target: ${result.Target}`);

                const processedVulnerabilities = processVulnerabilities(result, result.Target);

                // Log dettagliato delle vulnerabilità nel workflow
                Object.keys(processedVulnerabilities.vulnerabilities).forEach((severity) => {
                    processedVulnerabilities.vulnerabilities[severity].forEach((vuln) => {
                        core.info(`Vulnerability ID: ${vuln.VulnerabilityID} (Severity: ${severity})`);
                    });
                });

                summaryReport.imagesAnalyzed.push(processedVulnerabilities);
            }

            if (!result.Vulnerabilities && result.Target && result.Target !== "Node.js") {
                core.info(`Nessuna vulnerabilità trovata per ${result.Target}`);
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

                    pageTags.forEach((tag) => {
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
                const [versionA] = a.split("-alpine");
                const [versionB] = b.split("-alpine");

                return semver.compare(versionA, versionB);
            });
        };

        if (alpineTags.length > 0) {
            const sortedTags = sortTags(alpineTags);
            core.info("Alpine Tags ordinati:");
            sortedTags.forEach((tag) => core.info(`  Tag: ${tag}`));

            const top5Images = sortedTags.slice(0, 5);

            const trivyScan = async (image, reportFileName) => {
                const fullImageName = `library/node:${image}`;
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

                    const repository = process.env.GITHUB_REPOSITORY;
                    const runId = process.env.GITHUB_RUN_ID;
                    const reportLink = `https://github.com/${repository}/actions/runs/${runId}/artifacts`;

                    core.info(`Upload Trivy JSON Report for ${reportFileName}: ${reportLink}`);
                } catch (err) {
                    core.setFailed(`Errore nel caricamento del report per l'immagine ${reportFileName}: ${err}`);
                }
            };

            const parseTrivyReport = (image) => {
                const reportPath = `trivy-report-${image}.json`;
                const reportData = fs.readFileSync(reportPath, "utf8");
                const report = JSON.parse(reportData);

                report.Results.forEach((result) => {
                    if (result.Target && result.Target !== "Node.js") {
                        core.info(`Target: ${result.Target}`);

                        const processedVulnerabilities = processVulnerabilities(result, result.Target);

                        // Log dettagliato delle vulnerabilità nel workflow
                        Object.keys(processedVulnerabilities.vulnerabilities).forEach((severity) => {
                            processedVulnerabilities.vulnerabilities[severity].forEach((vuln) => {
                                core.info(`Vulnerability ID: ${vuln.VulnerabilityID} (Severity: ${severity})`);
                            });
                        });

                        summaryReport.imagesAnalyzed.push(processedVulnerabilities);
                    }
                });
            };

            for (const image of top5Images) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    const reportFileName = `trivy-report-${image}.json`;

                    await trivyScan(image, reportFileName);
                    await uploadArtifactForImage(reportFileName);
                    parseTrivyReport(image);

                    await sleep(2000);
                } catch (err) {
                    core.setFailed(`Errore nella scansione di ${image}: ${err}`);
                }
            }

            // Aggiungi conteggio delle iterazioni al report
            summaryReport.iterationCount = top5Images.length;

            // Salva il report finale
            fs.writeFileSync("summary-report.json", JSON.stringify(summaryReport, null, 2));
            core.info("Summary report generated successfully!");

            // Carica il report come artifact
            const artifactClient = artifact.create();
            await artifactClient.uploadArtifact("summary-report.json", ["summary-report.json"], ".");

        } else {
            core.info("Non sono stati trovati tag Alpine più recenti.");
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
