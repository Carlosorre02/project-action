const fs = require('fs');

// Percorso del report Trivy
const reportPath = './trivy-report.json'; // Specifica il percorso corretto del report JSON

fs.readFile(reportPath, "utf8", (err, data) => {
    if (err) {
        console.error("Error reading the report:", err);
        return;
    }

    let report;
    try {
        report = JSON.parse(data);
    } catch (parseError) {
        console.error("Error parsing the report:", parseError);
        return;
    }

    console.log(report); // Verifica il contenuto del report

    if (report.ArtifactName) {
        console.log("Artifact Name:", report.ArtifactName);
        const artifactNameParts = report.ArtifactName.split("/");
        console.log(artifactNameParts);
    } else {
        console.error("ArtifactName non trovato nel report.");
    }
});
