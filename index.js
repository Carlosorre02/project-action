const axios = require('axios');
const semver = require('semver');  // Aggiungiamo la libreria semver per il confronto delle versioni

const baseImage = 'node:18.20.2-alpine';

async function getTags() {
    const [namespace, repository] = baseImage.split(":")[0].split("/");
    const baseVersion = baseImage.split(":")[1].split("-")[0];  // Versione base, es. "18.20.2"

    const url = `https://hub.docker.com/v2/repositories/${namespace || 'library'}/${repository}/tags`;
    try {
        const response = await axios.get(url);
        const tags = response.data.results;

        // Filtra i tag per includere solo quelli rilevanti
        const relevantTags = tags
            .map(tag => tag.name)
            .filter(tag => {
                // Filtra i tag che corrispondono a pattern come "alpine", "bookworm", "slim", ecc.
                return (
                    /-alpine/.test(tag) || 
                    /-bookworm/.test(tag) || 
                    /-slim/.test(tag) || 
                    /-bullseye/.test(tag) || 
                    semver.valid(tag.split("-")[0]) // Includi anche le versioni semantiche valide
                );
            });

        // Filtra ulteriormente i tag con la versione semantica maggiore di quella base
        const higherVersionTags = relevantTags.filter(tag => {
            const versionPart = tag.split("-")[0];  // Estrai la parte della versione prima del trattino
            return semver.valid(versionPart) && semver.gt(versionPart, baseVersion);
        });

        // Output finale organizzato
        console.log("Lista dei tag filtrati e organizzati:");
        console.log(higherVersionTags);

    } catch (error) {
        console.error("Errore nella chiamata API o nel filtraggio dei tag:", error);
    }
}

getTags();
