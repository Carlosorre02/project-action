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
        if (result.Target && !result.Target.includes("Node.js")) {  // Ignora il target Node.js
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

            // Estrai la major, minor, e patch version dall'immagine base e la piattaforma
            const [baseMajor, baseMinor, basePatch] = currentTag.split(":")[1].split(".").slice(0, 3);
            const basePlatformPrefix = currentTag.includes("-") ? currentTag.split("-").pop().split(".")[0] : "";

            core.info(`Base Major.Minor.Patch: ${baseMajor}.${baseMinor}.${basePatch}`);
            core.info(`Base Platform Prefix: ${basePlatformPrefix}`);

            while (url) {
                try {
                    const response = await axios.get(url);
                    const pageTags = response.data.results;

                    if (!pageTags.length) {
                        core.setFailed("No tags found for the specified repository.");
                        process.exit(1);
                    }

                    pageTags.forEach((tag) => {
                        const tagVersion = tag.name;
                        
                        // Log di debug per ogni tag ottenuto
                        core.info(`Esaminando tag: ${tagVersion}`);

                        // Filtra solo i tag che corrispondono alla versione base e hanno un'incrementazione solo nella piattaforma
                        if (
                            tagVersion.startsWith(`${baseMajor}.${baseMinor}.${basePatch}-`) &&
                            tagVersion.includes(`${basePlatformPrefix}.`) &&
                            semver.valid(tagVersion.split("-")[0])
                        ) {
                            core.info(`Tag accettato: ${tagVersion}`);
                            tags.push(tag.name);
                        } else {
                            core.info(`Tag scartato: ${tagVersion}`);
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
                if (semver.valid(a.split("-")[0]) && semver.valid(b.split("-")[0])) {
                    return semver.compare(a.split("-")[0], b.split("-")[0]); // Ordine crescente
                }
                return 0;
            });
        };

        const currentTag = artifactName;
        const availableTags = await getTags(namespace, repository, currentTag);

        if (availableTags.length > 0) {
            const sortedTags = sortTags(availableTags); // Ordinati in ordine crescente
            core.info("Tag disponibili ordinati:");
            sortedTags.forEach((tag) => core.info(`Tag: ${tag}`));

            for (const image of sortedTags) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    const reportFileName = `trivy-report-${image}.json`;

                    await trivyScan(namespace, repository, image, reportFileName);
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

            // Genera il log finale per l'immagine migliore
            generateBestImageLog();

        } else {
            core.info("Non sono stati trovati tag più recenti.");
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
