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
    severity: "LOW, MEDIUM, HIGH, CRITICAL",
    iterationCount: 0,
    versionSelectionLogic: "Le versioni successive sono ordinate in base alla versione semantica, dalla più vecchia alla più recente (crescente).",
    imagesAnalyzed: [],
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

// Funzione per parsare e visualizzare le vulnerabilità dell'immagine base
const parseBaseImageReport = () => {
    const reportData = fs.readFileSync(reportPath, "utf8");
    const report = JSON.parse(reportData);

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

        // Esegui la scansione dell'immagine base e stampa i risultati
        parseBaseImageReport();

        // Estrarre il namespace e il repository dall'immagine base
        const parts = artifactName.split(":")[0].split("/");
        let namespace = "library";
        let repository = parts[0];
        let basePlatform = artifactName.includes("-") ? artifactName.split("-").pop() : "";

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);
        core.info(`Platform: ${basePlatform || "none specified"}`);

        const getTags = async (namespace, repository, currentTag) => {
            let url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags/?page_size=100`;
            let tags = [];

            // Estrai la major version dall'immagine base
            const baseMajorVersion = currentTag.split(":")[1].split(".")[0];

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
                        const tagPlatform = tag.name.includes("-") ? tag.name.split("-").pop() : "";

                        // Filtra solo i tag con la stessa major version e piattaforma dell'immagine base
                        if (
                            semver.valid(tagVersion) &&
                            semver.gt(tagVersion, currentVersion) &&
                            semver.major(tagVersion) === parseInt(baseMajorVersion) &&
                            (
                                (basePlatform && tagPlatform === basePlatform) || // Entrambi devono avere la stessa piattaforma
                                (!basePlatform && !tagPlatform) // Nessuno dei due ha una piattaforma
                            )
                        ) {
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

        // Funzione di ordinamento dei tag in ordine crescente
        const sortTags = (tags) => {
            return tags.sort((a, b) => {
                if (semver.valid(a) && semver.valid(b)) {
                    return semver.compare(a, b); // Ordine crescente
                }
                return 0;
            });
        };

        const currentTag = artifactName;
        const availableTags = await getTags(namespace, repository, currentTag);

        if (availableTags.length > 0) {
            const sortedTags = sortTags(availableTags); // Ordinati in ordine crescente
            core.info("Tag disponibili ordinati:");
            sortedTags.forEach((tag) => core.info(`  Tag: ${tag}`));

            for (const image of sortedTags) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    const reportFileName = `trivy-report-${image}.json`;

                    await trivyScan(image, reportFileName);
                    await uploadArtifactForImage(reportFileName);
                    parseTrivyReport(image);

                    await sleep(2000);  // Ritardo tra le scansioni
                } catch (err) {
                    core.setFailed(`Errore nella scansione di ${image}: ${err}`);
                }
            }

            summaryReport.iterationCount = sortedTags.length;

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

// Funzione per eseguire la scansione Trivy e generare il report
const trivyScan = async (image, reportFileName) => {
    const fullImageName = `${namespace}/${repository}:${image}`;
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

// Funzione per caricare il report Trivy come artifact
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

// Funzione per parsare il report Trivy per ogni immagine
const parseTrivyReport = (image) => {
    const reportPath = `trivy-report-${image}.json`;
    const reportData = fs.readFileSync(reportPath, "utf8");
    const report = JSON.parse(reportData);

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
};
