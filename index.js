const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const semver = require('semver');
const { exec } = require('child_process');

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

        // Usare ArtifactName per determinare il namespace e il repository
        const parts = artifactName.split(":")[0].split("/");

        let namespace = "library";  // Impostazione predefinita per immagini Docker ufficiali
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

                    // Estrazione della versione da "node:18.20.2-alpine" -> "18.20.2"
                    const currentVersion = currentTag.split(":")[1].split("-alpine")[0];

                    // Filtra e aggiungi solo i tag che contengono "alpine" e che sono versioni valide semver maggiori della corrente
                    pageTags.forEach(tag => {
                        const tagVersion = tag.name.split("-alpine")[0]; // Estrarre la parte di versione

                        // Controllare che il tag rappresenti una versione semver valida
                        if (tag.name.includes("alpine") && semver.valid(tagVersion) && semver.gt(tagVersion, currentVersion)) {
                            tags.push(tag.name);
                        }
                    });

                    // Se c'è una pagina successiva, aggiornare l'URL per ottenere la pagina successiva
                    url = response.data.next;
                } catch (apiErr) {
                    core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
                    process.exit(1);
                }
            }

            return tags;
        };

        // Esempio di chiamata alla funzione
        const currentTag = artifactName;  // L'immagine base
        const alpineTags = await getAlpineTags(namespace, repository, currentTag);

        // Funzione di ordinamento avanzata
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

        // Stampa dei tag ottenuti e ordinamento
        if (alpineTags.length > 0) {
            const sortedTags = sortTags(alpineTags);
            core.info("Alpine Tags ordinati:");
            sortedTags.forEach(tag => core.info(`  Tag: ${tag}`));

            // Scansione delle prime 5 immagini
            const top5Images = sortedTags.slice(0, 5);

            const trivyScan = async (image) => {
                return new Promise((resolve, reject) => {
                    exec(`trivy image --severity CRITICAL,HIGH --format json --output trivy-report-${image}.json ${image}`, (error, stdout, stderr) => {
                        if (error) {
                            reject(`Errore durante la scansione di Trivy per l'immagine ${image}: ${stderr}`);
                        } else {
                            resolve(`Trivy report per ${image} salvato.`);
                        }
                    });
                });
            };

            for (const image of top5Images) {
                core.info(`Inizio scansione per immagine: ${image}`);
                try {
                    await trivyScan(image);
                    core.info(`Scansione completata per immagine: ${image}`);
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
