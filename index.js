const fs = require("fs"); 
const core = require("@actions/core");
const axios = require("axios");
const semver = require('semver');
const { exec } = require('child_process');
const { mv } = require('shelljs'); // Aggiungi shelljs per spostare i file

// Funzione per aggiungere un ritardo
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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

        // Iterare attraverso i risultati del report
        report.Results.forEach(result => {
            if (result.Target && result.Target !== "Node.js") {
                core.info(`Target: ${result.Target}`);
            }

            const relevantVulns = extractVulnInfo(result.Vulnerabilities || []);

            relevantVulns.forEach(vulnInfo => {
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

        // Usare ArtifactName per determinare il namespace e il repository
        const parts = artifactName.split(":")[0].split("/");

        let namespace = "library";  
        let repository = parts[0];

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);

        // Funzione per ottenere tutti i tag che contengono "alpine" e attraversare le pagine
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

            const top5Images = sortedTags.slice(0, 5);

            const trivyScan = async (image) => {
                const fullImageName = `library/node:${image}`;
                return new Promise((resolve, reject) => {
                    exec(`trivy image --format json --output trivy-report-${image}.json --severity MEDIUM,HIGH,CRITICAL ${fullImageName}`, (error, stdout, stderr) => {
                        if (error) {
                            reject(`Errore durante la scansione di Trivy per l'immagine ${fullImageName}: ${stderr}`);
                        } else {
                            resolve(`Trivy report per ${fullImageName} salvato.`);
                        }
                    });
                });
            };

            const uploadReport = (image) => {
                const artifactPath = `trivy-report-${image}.json`;
                const destPath = `./reports/trivy-report-${image}.json`; // Sposta nella cartella reports
                mv(artifactPath, destPath);
                core.info(`Upload del report per ${artifactPath}`);
                core.setOutput('report-path', destPath);
            };

            const parseTrivyReport = (image) => {
                const reportPath = `trivy-report-${image}.json`;
                const reportData = fs.readFileSync(reportPath, "utf8");
                const report = JSON.parse(reportData);

                report.Results.forEach(result => {
                    if (result.Target && result.Target !== "Node.js") {
                        core.info(`Target: ${result.Target}`);
                    }

                    const vulnerabilities = result.Vulnerabilities || [];

                    if (vulnerabilities.length > 0) {
                        vulnerabilities.forEach(vuln => {
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

                // Carica il report come artefatto
                uploadReport(image);
            };

            for (const image of top5Images) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    await trivyScan(image);
                    parseTrivyReport(image);
                    await sleep(10000);
                } catch (err) {
                    core.setFailed(`Errore nella scansione di ${image}: ${err}`);
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
