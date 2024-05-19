const core = require('@actions/core'); 
const github = require('@actions/github'); 

try { 
  // input `who-to-greet` definito nel file di metadati dell'azione 
  const nameToGreet = core.getInput('who-to-greet'); 
  console.log(`Ciao ${nameToGreet}!`); 

  const time = (new Date()).toTimeString(); 
  core.setOutput("time", time); 

  // Ottieni il payload del webhook JSON per l'evento che ha attivato il flusso di lavoro 
  const payload = JSON.stringify(github.context.payload, null, 2); 
  console.log(`The event payload: ${payload}`); 
} catch (error) { 
  core.setFailed(error.message); 
}
