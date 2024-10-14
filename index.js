const core = require('@actions/core');
const axios = require('axios');
const semver = require('semver');
const fs = require('fs');

async function parseTrivyReport() {
    try {
        const reportPath = core.getInput('report-path');
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));

        const baseImage = core.getInput('base-image');
        const targetImage = core.getInput('target-image');
        const vulnerabilities = report.Results[0].Vulnerabilities || [];

        core.info(`Base Image: ${baseImage}`);
        core.info(`Target: ${targetImage}`);

        vulnerabilities.forEach(vuln => {
            core.info(`Package: ${vuln.PkgName}`);
            core.info(`Vulnerability ID: ${vuln.VulnerabilityID}`);
            core.info(`Severity: ${vuln.Severity}`);
            core.info(`Installed Version: ${vuln.InstalledVersion}`);
            core.info(`Fixed Version: ${vuln.FixedVersion}`);
            core.info('---');
        });

        // Elenco delle versioni successive dell'immagine Docker ordinato
        const namespace = core.getInput('namespace');
        const repository = core.getInput('repository');
        const baseTag = core.getInput('base-tag');

        const sortedTags = await getSortedDockerTags(namespace, repository, baseTag);
        core.info(`Alpine Tags ordinati:`);
        sortedTags.forEach(tag => core.info(`  Tag: ${tag}`));

        for (const tag of sortedTags) {
            core.info(`Inizio scansione per immagine: ${tag}`);
            // Esegui qui la scansione con Trivy per ogni tag successivo
            const scanResult = await runTrivyScan(tag);
            if (scanResult.success) {
                core.info(`Report per ${tag} caricato.`);
            } else {
                core.setFailed(`Errore nella scansione di ${tag}: ${scanResult.error}`);
            }
        }

        // Rimuovo i log dettagliati dell'upload artifact
        await uploadSummaryReport(report);

    } catch (error) {
        core.setFailed(`Error parsing the report: ${error.message}`);
    }
}

async function getSortedDockerTags(namespace, repository, baseTag) {
    const url = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags?page_size=100`;
    const response = await axios.get(url);
    const tags = response.data.results.map(tag => tag.name);

    // Ordina i tag con semver
    const filteredTags = tags.filter(tag => semver.valid(tag) && semver.gt(tag, baseTag));
    return filteredTags.sort(semver.compare);
}

async function runTrivyScan(tag) {
    // Implementa qui la logica per eseguire la scansione con Trivy e restituire un risultato
    return { success: true };
}

async function uploadSummaryReport(report) {
    const summaryPath = core.getInput('summary-path');
    fs.writeFileSync(summaryPath, JSON.stringify(report));
    core.info('Summary report generated successfully!');
}

parseTrivyReport();
