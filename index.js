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

        // Log dell'immagine base
        core.info(`Base Image: ${artifactName}`);

        // Funzione per estrarre informazioni rilevanti da ogni vulnerabilità
        const extractVulnInfo = (vulnerabilities) => {
            return vulnerabilities.map((vuln) => {
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

        // Iterare attraverso i risultati del report
        report.Results.forEach((result) => {
            if (result.Target && result.Target !== "Node.js") {
                core.info(`Target: ${result.Target}`);
            }

            const relevantVulns = extractVulnInfo(result.Vulnerabilities || []);

            relevantVulns.forEach((vulnInfo) => {
                core.info(`Package: ${vulnInfo.PkgName}`);
                core.info(`Vulnerability ID: ${vulnInfo.VulnerabilityID}`);
                core.info(`Severity: ${vulnInfo.Severity}`);
                core.info(`Installed Version: ${vulnInfo.InstalledVersion}`);
                core.info(`Fixed Version: ${vulnInfo.FixedVersion}`);
                core.info("---");
            });

            if (relevantVulns.length === 0 && result.Target && result.Target !== "Node.js") {
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
                        `trivy image --format json --output ${reportFileName} --severity MEDIUM,HIGH,CRITICAL ${fullImageName}`,
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

                    // Log minimale
                    core.info(`Report per ${reportFileName} caricato.`);
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
                    }

                    const vulnerabilities = result.Vulnerabilities || [];

                    if (vulnerabilities.length > 0) {
                        vulnerabilities.forEach((vuln) => {
                            core.info(`Package: ${vuln.PkgName}`);
                            core.info(`Vulnerability ID: ${vuln.VulnerabilityID}`);
                            core.info(`Severity: ${vuln.Severity}`);
                            core.info(`Installed Version: ${vuln.InstalledVersion}`);
                            core.info(`Fixed Version: ${vuln.FixedVersion || "No fix available"}`);
                            core.info("---");
                        });
                    } else if (result.Target && result.Target !== "Node.js") {
                        core.info(`Nessuna vulnerabilità trovata per ${result.Target}`);
                    }
                });
            };

            const summaryReport = {
                baseImage: artifactName,
                severityUsed: "MEDIUM,HIGH,CRITICAL",
                iterations: top5Images.length,
                vulnerabilities: []
            };

            for (const image of top5Images) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    const reportFileName = `trivy-report-${image}.json`;

                    await trivyScan(image, reportFileName);
                    await uploadArtifactForImage(reportFileName);
                    parseTrivyReport(image);

                    const reportData = JSON.parse(fs.readFileSync(reportFileName, "utf8"));
                    summaryReport.vulnerabilities.push({
                        image: image,
                        vulnerabilities: reportData.Results
                    });

                    await sleep(10000);
                } catch (err) {
                    core.setFailed(`Errore nella scansione di ${image}: ${err}`);
                }
            }

            // Salva il report di riepilogo come JSON
            fs.writeFileSync("summary-report.json", JSON.stringify(summaryReport, null, 2));

            // Funzione di caricamento del report di riepilogo
            const uploadSummaryReport = async () => {
                try {
                    const artifactClient = artifact.create();
                    await artifactClient.uploadArtifact("summary-report.json", ["summary-report.json"], '.');
                    core.info("Report riassuntivo caricato con successo.");
                } catch (err) {
                    core.setFailed(`Errore nel caricamento del report riassuntivo: ${err}`);
                }
            };

            await uploadSummaryReport();

        } else {
            core.info("Non sono stati trovati tag Alpine più recenti.");
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
