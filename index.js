const fs = require("fs");
const core = require("@actions/core");
const { exec } = require("child_process");
const artifact = require("@actions/artifact");

// Funzione per aggiungere un ritardo
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Ottieni il percorso del report Trivy dall'input
const reportPath = core.getInput("trivy-report");

if (!reportPath) {
    core.setFailed("Report path is required");
    process.exit(1);
}

// Funzione per caricare il report come artefatto e fornire il link al download
const uploadArtifactForImage = async (reportFileName) => {
    try {
        const artifactClient = artifact.create();
        await artifactClient.uploadArtifact(reportFileName, [reportFileName], '.');

        // Ottieni i dettagli del repository e del run corrente per il link
        const repository = process.env.GITHUB_REPOSITORY;
        const runId = process.env.GITHUB_RUN_ID;
        const reportLink = `https://github.com/${repository}/actions/runs/${runId}/artifacts`;

        // Mostra solo il messaggio con il link al report
        core.info(`Upload Trivy JSON Report for ${reportFileName}: ${reportLink}`);
    } catch (err) {
        core.setFailed(`Errore nel caricamento del report per l'immagine ${reportFileName}: ${err}`);
    }
};

// Funzione per eseguire la scansione Trivy e salvare il report
const trivyScan = async (image, reportFileName) => {
    const fullImageName = `library/node:${image}`;
    return new Promise((resolve, reject) => {
        exec(
            `trivy image --format json --output ${reportFileName} --severity MEDIUM,HIGH,CRITICAL ${fullImageName}`,
            (error, stdout, stderr) => {
                if (error) {
                    reject(`Errore durante la scansione di Trivy per l'immagine ${fullImageName}: ${stderr}`);
                } else {
                    resolve(`Trivy report per ${fullImageName} salvato.`);
                }
            }
        );
    });
};

// Legge e analizza il report di Trivy
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

        // Crea un elenco di immagini ordinate da scansionare
        const top5Images = ['18.20.3-alpine3.20', '18.20.3-alpine3.19', '18.20.3-alpine', '18.20.3-alpine3.18', '18.20.4-alpine3.20'];

        // Cicla attraverso le immagini e carica i report come artefatti
        for (const image of top5Images) {
            core.info(`Inizio scansione per immagine: ${image}`);
            try {
                const reportFileName = `trivy-report-${image}.json`;

                // Esegui la scansione e carica il report
                await trivyScan(image, reportFileName);
                await uploadArtifactForImage(reportFileName);

                // Aggiungi un ritardo di 10 secondi tra le scansioni
                await sleep(10000);
            } catch (err) {
                core.setFailed(`Errore nella scansione di ${image}: ${err}`);
            }
        }
    } catch (parseErr) {
        core.setFailed(`Error parsing the report: ${parseErr.message}`);
        process.exit(1);
    }
});
