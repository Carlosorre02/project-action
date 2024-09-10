const fs = require("fs");  // Per lavorare con il file system
const core = require("@actions/core");  // Per interagire con le GitHub Actions
const axios = require("axios");  // Per effettuare richieste HTTP

// Ottenere il percorso del report Trivy dall'input di GitHub Actions
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

        // Controlliamo se artifactName è definito e stampiamo il report per verificarne il contenuto
        core.info(`Report: ${JSON.stringify(report, null, 2)}`);

        if (!artifactName) {
            core.setFailed("ArtifactName is undefined or missing in the report.");
            process.exit(1);
        }

        core.info(`ArtifactName: ${artifactName}`);

        // Aggiungiamo un controllo per il formato dell'ArtifactName
        if (artifactName.includes("***")) {
            core.setFailed("ArtifactName contains masked or incomplete data.");
            process.exit(1);
        }

        // Verifica il formato corretto prima dello split
        const parts = artifactName.split("/");

        if (parts.length < 3) {
            core.setFailed(`ArtifactName is not in the expected format: ${artifactName}`);
            process.exit(1);
        }

        const fullRegistry = parts[0]; // docker.io
        const namespace = parts[1]; // carlo02sorre
        const repositoryWithTag = parts[2]; // demonode:main
        const repository = repositoryWithTag.split(":")[0]; // demonode

        core.info(`Full Registry: ${fullRegistry}`);
        core.info(`Namespace: ${namespace}`);
        core.info(`Repository: ${repository}`);

        // Corretto URL per recuperare i tag
        const url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags`;
        core.info(`Fetching tags from: ${url}`);

        try {
            const response = await axios.get(url);
            const tags = response.data.results;

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
