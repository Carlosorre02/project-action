const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const semver = require('semver');
const { exec } = require("child_process");

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

        // Funzione per eseguire lo scanner Trivy
        const runTrivyScanner = (imageTag, callback) => {
            core.info(`Eseguendo la scansione di: ${imageTag}`);

            const command = `trivy image --format json --output ${imageTag}-trivy-report.json ${imageTag}`;

            exec(command, (err, stdout, stderr) => {
                if (err) {
                    core.setFailed(`Errore durante la scansione di ${imageTag}: ${err.message}`);
                    return;
                }
                if (stderr) {
                    core.info(`stderr: ${stderr}`);
                }
                core.info(`Risultato della scansione per ${imageTag}: ${stdout}`);
                callback();  // Chiamata per procedere al tag successivo
            });
        };

        // Funzione per eseguire il loop sui primi 5 tag
        const scanNextTag = (tags, index = 0) => {
            if (index >= 5 || index >= tags.length) {
                core.info("La scansione dei primi 5 tag è completata.");
                return;
            }

            const currentTag = tags[index];
            runTrivyScanner(currentTag, () => {
                scanNextTag(tags, index + 1);  // Scansiona il tag successivo
            });
        };

        // Esegui l'estrazione dei tag e poi la scansione
        const currentTag = artifactName;  // L'immagine base
        const alpineTags = await getAlpineTags(namespace, repository, currentTag);

        // Ordina i tag in ordine crescente
        const sortedTags = alpineTags.sort((a, b) => {
            const versionA = a.split("-alpine")[0];
            const versionB = b.split("-alpine")[0];
            return semver.compare(versionA, versionB);
        });

        // Stampa i tag ordinati
        if (sortedTags.length > 0) {
            core.info("Alpine Tags ordinati:");
            sortedTags.forEach(tag => core.info(`  Tag: ${tag}`));

            // Scansiona i primi 5 tag ordinati
            scanNextTag(sortedTags);
        } else {
            core.info("Non sono stati trovati tag Alpine più recenti.");
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
