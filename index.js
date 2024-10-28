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

let vulnerabilityCounts = {};

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

    // Conta il numero di vulnerabilità per gravità, impostando un valore predefinito se non ci sono vulnerabilità
    const countBySeverity = {
        CRITICAL: cveBySeverity.CRITICAL.length || 0,
        HIGH: cveBySeverity.HIGH.length || 0,
        MEDIUM: cveBySeverity.MEDIUM.length || 0,
        LOW: cveBySeverity.LOW.length || 0,
    };

    vulnerabilityCounts[target] = countBySeverity; // Aggiungi i conteggi al report
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

        const findBestImage = () => {
            let bestImage = summaryReport.baseImage;
            let baseCounts = vulnerabilityCounts[bestImage];
            let tied = true;

            for (const [image, counts] of Object.entries(vulnerabilityCounts)) {
                if (image !== bestImage) {
                    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
                        if (counts[severity] < baseCounts[severity]) {
                            bestImage = image;
                            baseCounts = counts;
                            tied = false;
                            break;
                        } else if (counts[severity] > baseCounts[severity]) {
                            tied = false;
                            break;
                        }
                    }
                }
            }
            if (tied) {
                core.info(`Tutte le immagini hanno lo stesso numero di vulnerabilità. L'immagine base è considerata la migliore.`);
                return summaryReport.baseImage;
            }
            return bestImage;
        };

        // Calcola e stampa il risultato finale
        const bestImage = findBestImage();
        core.info(`L'immagine migliore è: ${bestImage}`);
        summaryReport.bestImage = bestImage;

        // Scrivi il report riassuntivo
        fs.writeFileSync("summary-report.json", JSON.stringify(summaryReport, null, 2));
        core.info("Summary report generated successfully!");

        // Carica il report come artifact
        const artifactClient = artifact.create();
        await artifactClient.uploadArtifact("summary-report.json", ["summary-report.json"], ".");
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
