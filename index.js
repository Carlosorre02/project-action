const core = require('@actions/core'); 
const github = require('@actions/github'); 

try { 
  // input `who-to-greet` definito nel file di metadati dell'azione 
  const nameToGreet = core.getInput('who-to-greet'); 
  console.log(`Ciao ${nomeal saluto}!`); 
  const time = (new Date()).toTimeString(); 
  core.setOutput("ora", ora); 
  // Ottieni il payload del webhook JSON per l'evento che ha attivato il flusso di lavoro 
  const payload = JSON.stringify(github.context.payload, unfined, 2) 
  console.log(`The event payload: ${payload}`); 
} catch (errore) { 
  core.setFailed(error.message); 
}

