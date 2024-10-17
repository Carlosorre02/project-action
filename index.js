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
    imagesAnalyzed: [], // Dettagli sulle immagini analizzate
};

// Funzione per estrarre solo i CVE delle vulnerabilità separate per gravità
const extractCveBySeverity = (vulnerabilities) => {
    const cveBySeverity = { LOW: [], MEDIUM: [], HIGH: [], CRITICAL: [] };

    vulnerabilities.forEach((vuln) => {
        if (vuln.VulnerabilityID) {
            cveBySeverity[vuln.Severity.toUpperCase()].push(vuln.VulnerabilityID);
        }
    });

    return cveBySeverity;
};

// Funzione per iterare attraverso i risultati e separare solo i CVE per gravità
const processCve = (results, target) => {
    const vulnerabilities = results.Vulnerabilities || [];
    const cveBySeverity = extractCveBySeverity(vulnerabilities);

    return {
        target,
        vulnerabilities: cveBySeverity,
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
            core.info(`Target: ${result.Target}`);

            const relevantVulns = result.Vulnerabilities || [];
            
            relevantVulns.forEach((vuln) => {
                // Manteniamo l'output dettagliato nel workflow
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

            // Aggiungi le informazioni dei CVE al report riassuntivo
            const processedCve = processCve(result, result.Target);
            summaryReport.imagesAnalyzed.push(processedCve);
        });

        // Funzione per ottenere i tag successivi
        const getNextTags = async (namespace, repository, currentTag) => {
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

                    // Aggiungi solo le versioni successive a currentVersion
                    pageTags.forEach((tag) => {
                        const tagVersion = tag.name;
                        if (semver.valid(tagVersion) && semver.gt(tagVersion, currentVersion)) {
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
        const namespace = "library";
        const repository = artifactName.split(":")[0];

        // Ottieni le versioni successive
        const nextTags = await getNextTags(namespace, repository, currentTag);

        if (nextTags.length > 0) {
            const top5Images = nextTags.slice(0, 5);

            // Definizione della funzione trivyScan
            const trivyScan = async (image, reportFileName) => {
                return new Promise((resolve, reject) => {
                    exec(
                        `trivy image --format json --output ${reportFileName} --severity LOW,MEDIUM,HIGH,CRITICAL ${image}`,
                        (error, stdout, stderr) => {
                            if (error) {
                                reject(`Errore durante la scansione di Trivy per l'immagine ${image}: ${stderr}`);
                            } else {
                                resolve(`Trivy report per ${image} salvato.`);
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

                    // Aggiungi solo i CVE al report riassuntivo
                    const processedCve = processCve(result, result.Target);
                    summaryReport.imagesAnalyzed.push(processedCve);
                });
            };

            // Ciclo per scansionare le immagini successive
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
            core.info("Non sono stati trovati tag più recenti.");
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
