const axios = require('axios');
const fs = require('fs');
const semver = require('semver');

async function getTagsFromDockerHub(imageBase) {
    const namespace = 'library'; // Modifica il namespace in base alle tue necessità
    const repository = 'node'; // Modifica il repository in base alle tue necessità

    try {
        const response = await axios.get(`https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags`);
        return response.data.results.map(tag => tag.name);
    } catch (error) {
        console.error('Errore durante il recupero dei tag da Docker Hub:', error.message);
        return [];
    }
}

function printVulnerabilities(vulnerabilities) {
    vulnerabilities.forEach(vuln => {
        console.log(`Package: ${vuln.PkgName}`);
        console.log(`Vulnerability ID: ${vuln.VulnerabilityID}`);
        console.log(`Severity: ${vuln.Severity}`);
        console.log(`Installed Version: ${vuln.InstalledVersion}`);
        console.log(`Fixed Version: ${vuln.FixedVersion}`);
        console.log('---');
    });
}

function scanBaseImageReport(report, imageName) {
    console.log(`Inizio scansione per immagine: ${imageName}`);

    const baseImage = report.ArtifactName;
    console.log(`Target: ${baseImage}`);

    if (report.Results && report.Results.length > 0) {
        report.Results.forEach(result => {
            if (result.Vulnerabilities && result.Vulnerabilities.length > 0) {
                printVulnerabilities(result.Vulnerabilities);
            }
        });
    }

    console.log(`Fine scansione per immagine: ${imageName}`);
}

function scanNodeJsVulnerabilities(report) {
    const nodeJsResults = report.Results.find(result => result.Target === 'Node.js');
    
    if (nodeJsResults && nodeJsResults.Vulnerabilities && nodeJsResults.Vulnerabilities.length > 0) {
        console.log('Vulnerabilità trovate per Node.js:');
        printVulnerabilities(nodeJsResults.Vulnerabilities);
    } else {
        console.log('Target: Node.js');
        console.log('Nessuna vulnerabilità trovata per Node.js');
    }
}

async function run() {
    try {
        // Leggi il report JSON generato da Trivy
        const trivyReport = JSON.parse(fs.readFileSync('./trivy-report.json', 'utf-8'));

        // Estrai i tag ordinati per l'immagine base
        const imageBase = 'node:18.20.2-alpine';
        const tags = await getTagsFromDockerHub(imageBase);

        console.log('Alpine Tags ordinati:');
        tags.forEach(tag => console.log(`  Tag: ${tag}`));

        // Scansione di ciascuna immagine ordinata per tag
        tags.forEach(tag => {
            const imageName = `${imageBase.split(':')[0]}:${tag}`;
            scanBaseImageReport(trivyReport, imageName);
            scanNodeJsVulnerabilities(trivyReport); // Esegui la scansione di Node.js separatamente dopo la scansione dell'immagine
        });
    } catch (error) {
        console.error('Errore durante l\'esecuzione dell\'action:', error);
    }
}

run();
