const fs = require("fs");
const core = require("@actions/core");
const axios = require("axios");
const { execSync } = require("child_process");  // Per eseguire comandi shell

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

        // Log del report per verificarne il contenuto
        core.info(`Report: ${JSON.stringify(report, null, 2)}`);

        if (!artifactName) {
            core.setFailed("ArtifactName is undefined or missing in the report.");
            process.exit(1);
        }

        core.info(`ArtifactName (Base Image): ${artifactName}`);

        // Usare ArtifactName per determinare il namespace e il repository
        const parts = artifactName.split(":")[0].split("/");

        if (parts.length < 1) {
            core.setFailed(`ArtifactName is not in the expected format: ${artifactName}`);
            process.exit(1);
        }

        let namespace = "library";  // Impostazione predefinita per immagini Docker ufficiali
        let repository = parts[0];

        if (parts.length === 2) {
            namespace = parts[0];
            repository = parts[1];
        }

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
            for (const tag of tags) {
                const tagName = tag.name;
                core.info(`  Tag: ${tagName}, Is Current: ${tag.is_current}`);

                // Esegui la scansione Trivy per ogni tag
                await runTrivyScan(`${namespace}/${repository}:${tagName}`);
            }

        } catch (apiErr) {
            core.setFailed(`Error fetching tags from Docker Hub: ${apiErr.message}`);
            process.exit(1);
        }

    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});

// Funzione per eseguire Trivy su una specifica immagine
async function runTrivyScan(image) {
    core.info(`Running Trivy scan for image: ${image}`);
    try {
        const outputFilePath = `trivy-report-${image.replace(/[:/]/g, "_")}.json`;

        // Esegue il comando Trivy
        execSync(`trivy image --format json --output ${outputFilePath} --severity CRITICAL,HIGH ${image}`, { stdio: "inherit" });

        core.info(`Trivy scan completed for image: ${image}, report saved to ${outputFilePath}`);
        core.setOutput(`trivy-report-${image}`, outputFilePath);
    } catch (err) {
        core.setFailed(`Failed to run Trivy scan for ${image}: ${err.message}`);
    }
}
