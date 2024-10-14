const core = require('@actions/core');
const axios = require('axios');
const semver = require('semver');
const fs = require('fs');

async function parseTrivyReport() {
    try {
        // Lettura del percorso del report e parsing del JSON
        const reportPath = core.getInput('report-path');
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

        // Recupero delle informazioni base dall'input
        const baseImage = core.getInput('base-image');
        const targetImage = core.getInput('target-image');
        const vulnerabilities = report.Results[0].Vulnerabilities || [];

        // Stampa delle informazioni sull'immagine base e target
        core.info(`Base Image: ${baseImage}`);
        core.info(`Target: ${targetImage}`);

        // Iterazione e stampa delle vulnerabilità
        vulnerabilities.forEach(vuln => {
            core.info(`Package: ${vuln.PkgName}`);
            core.info(`Vulnerability ID: ${vuln.VulnerabilityID}`);
            core.info(`Severity: ${vuln.Severity}`);
            core.info(`Installed Version: ${vuln.InstalledVersion}`);
            core.info(`Fixed Version: ${vuln.FixedVersion}`);
            core.info('---');
        });

        // Recupero delle informazioni sul namespace, repository e tag base
        const namespace = core.getInput('namespace');
        const repository = core.getInput('repository');
        const baseTag = core.getInput('base-tag');

        // Recupero e ordinamento dei tag dell'immagine Docker
        const sortedTags = await getSortedDockerTags(namespace, repository, baseTag);
        core.info(`Alpine Tags ordinati:`);
        sortedTags.forEach(tag => core.info(`  Tag: ${tag}`));

        // Scansione per ogni tag successivo
        for (const tag of sortedTags) {
            core.info(`Inizio scansione per immagine: ${tag}`);
            const scanResult = await runTrivyScan(tag);
            if (scanResult.success) {
                core.info(`Report per ${tag} caricato.`);
            } else {
                core.setFailed(`Errore nella scansione di ${tag}: ${scanResult.error}`);
            }
        }

        // Caricamento del report riassuntivo
        await uploadSummaryReport(report);

    } catch (error) {
        core.setFailed(`Error parsing the report: ${error.message}`);
    }
}

async function getSortedDockerTags(namespace, repository, baseTag) {
    try {
        // Costruzione dell'URL per ottenere i tag da Docker Hub
        const url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags?page_size=100`;
        const response = await axios.get(url);
        const tags = response.data.results.map(tag => tag.name);

        // Filtraggio e ordinamento dei tag con semver
        const filteredTags = tags.filter(tag => semver.valid(tag) && semver.gt(tag, baseTag));
        return filteredTags.sort(semver.compare);
    } catch (error) {
        core.setFailed(`Errore nel recupero dei tag da Docker Hub: ${error.message}`);
        return [];
    }
}

async function runTrivyScan(tag) {
    try {
        // Qui puoi implementare la logica per eseguire Trivy, simulato con un successo per ora
        // Simulazione di una scansione andata a buon fine
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function uploadSummaryReport(report) {
    try {
        const summaryPath = core.getInput('summary-path');
        fs.writeFileSync(summaryPath, JSON.stringify(report, null, 2));
        core.info('Summary report generated successfully!');
    } catch (error) {
        core.setFailed(`Errore durante il salvataggio del summary report: ${error.message}`);
    }
}

// Avvio del processo di parsing del report Trivy
parseTrivyReport();
