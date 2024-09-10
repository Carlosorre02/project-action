const fs = require("fs");  // Per lavorare con il file system
const core = require("@actions/core");  // Per interagire con le GitHub Actions
const axios = require("axios");  // Per effettuare richieste HTTP

// Ottieni il percorso del report Trivy dall'input di GitHub Actions
const reportPath = core.getInput("trivy-report");

// Ottieni l'immagine base dalla variabile d'ambiente BASE_IMAGE
const baseImage = process.env.BASE_IMAGE;

if (!reportPath) {
    core.setFailed("Report path is required");
    process.exit(1);
}

if (!baseImage) {
    core.setFailed("BASE_IMAGE environment variable is missing.");
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

        // Log del report per verificarne il contenuto
        core.info(`Report: ${JSON.stringify(report, null, 2)}`);

        if (!artifactName) {
            core.setFailed("ArtifactName is undefined or missing in the report.");
            process.exit(1);
        }

        core.info(`ArtifactName: ${artifactName}`);

        // Usare l'immagine base
        core.info(`Using Base Image: ${baseImage}`);

        // Estrazione del namespace e repository dall'immagine base
        const baseImageParts = baseImage.split("/");

        if (baseImageParts.length < 2) {
            core.setFailed(`Base Image format is invalid: ${baseImage}`);
            process.exit(1);
        }

        const namespace = baseImageParts[0];  // Prende il namespace dell'immagine
        const repositoryWithTag = baseImageParts[1]; // Prende il repository con eventuale tag
        const repository = repositoryWithTag.split(":")[0]; // Prende solo il repository senza il tag

        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);

        // Costruzione dell'URL per chiamare l'API di Docker Hub
        const url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags`;
        core.info(`Fetching tags from: ${url}`);

        try {
            const response = await axios.get(url);
            const tags = response.data.results;

            if (!tags.length) {
                core.setFailed("No tags found for the specified repository.");
                process.exit(1);
            }

            core.info("Tags:");
            tags.forEach(tag => {
                core.info(`  Tag: ${tag.name}, Is Current: ${tag.is_current}`);
            });
        } catch (apiErr) {
            core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
            process.exit(1);
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
