const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");

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

        core.info(`Base Image: ${artifactName}`);

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
        const getAlpineTags = async (namespace, repository) => {
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

                    // Filtra e aggiungi solo i tag che contengono "alpine"
                    pageTags.forEach(tag => {
                        if (tag.name.includes("alpine")) {
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

        // Ottenere i tag "alpine" e stamparli
        const alpineTags = await getAlpineTags(namespace, repository);

        if (alpineTags.length > 0) {
            core.info("Alpine Tags:");
            alpineTags.forEach(tag => core.info(`  Tag: ${tag}`));
        } else {
            core.info("No Alpine tags found.");
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
