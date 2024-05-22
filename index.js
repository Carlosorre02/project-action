const fs = require("fs");
const core = require("@actions/core");

const reportPath = core.getInput("trivy-report");



    try {
        console.log(reportPath);
    } catch (parseErr) {
        core.setFailed("Error parsing the report: ${parseErr.message}");
        process.exit(1);
    }

