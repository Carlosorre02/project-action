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

        const parts = artifactName.split(":")[0].split("/");

        let namespace = "library";  // Impostazione predefinita per immagini Docker ufficiali
        let repository = parts[0];

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);

        // Funzione per ottenere tutti i tag che contengono "alpine"
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

        if (alpineTags.length > 0) {
            core.info("Alpine Tags ordinati:");
            alpineTags.sort((a, b) => semver.compare(a.split('-alpine')[0], b.split('-alpine')[0]));
            alpineTags.forEach(tag => core.info(`  Tag: ${tag}`));
        } else {
            core.info("Non sono stati trovati tag Alpine più recenti.");
        }

        // Loop per eseguire Trivy sulle prime 5 immagini
        const topFiveTags = alpineTags.slice(0, 5);

        for (const tag of topFiveTags) {
            const imageName = `${namespace}/${repository}:${tag}`;
            const outputReport = `${tag}-trivy-report.json`;

            core.info(`Eseguendo Trivy su: ${imageName}`);
            exec(`trivy image --format json --output ${outputReport} ${imageName}`, (err, stdout, stderr) => {
                if (err) {
                    core.setFailed(`Errore durante la scansione di ${tag}: ${err.message}`);
                    return;
                }
                core.info(`Report generato per ${tag}: ${outputReport}`);
            });
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
