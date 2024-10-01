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
        core.setFailed(Error reading the report: ${err.message});
        process.exit(1);
    }

    try {
        const report = JSON.parse(data);
        const artifactName = report.ArtifactName;

        // Log del report per verificarne il contenuto
        core.info(Report: ${JSON.stringify(report, null, 2)});

        if (!artifactName) {
            core.setFailed("ArtifactName is undefined or missing in the report.");
            process.exit(1);
        }

        core.info(ArtifactName (Base Image): ${artifactName});

        // Usare ArtifactName per determinare il namespace e il repository
        const parts = artifactName.split(":")[0].split("/");

        if (parts.length < 1) {
            core.setFailed(ArtifactName is not in the expected format: ${artifactName});
            process.exit(1);
        }

        let namespace = "library";  // Impostazione predefinita per immagini Docker ufficiali
        let repository = parts[0];

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

        core.info(Namespace: ${namespace});
        core.info(Repository: ${repository});

        // Costruzione dell'URL per chiamare l'API di Docker Hub
        const url = https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags;
        core.info(Fetching tags from: ${url});

        try {
            const response = await axios.get(url);
            const tags = response.data.results;

            if (!tags.length) {
                core.setFailed("No tags found for the specified repository.");
                process.exit(1);
            }

            core.info("Tags:");
            tags.forEach(tag => {
                core.info(  Tag: ${tag.name}, Is Current: ${tag.is_current});
            });
        } catch (apiErr) {
            core.setFailed(Error fetching tags from Docker Hub: ${apiErr.message});
            process.exit(1);
        }

    } catch (parseErr) {
        core.setFailed(Error parsing the report: ${parseErr.message});
        process.exit(1);
    }
});
