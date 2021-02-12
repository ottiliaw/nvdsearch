#!/usr/bin/env node
const yargs = require("yargs");
const fs = require('fs');

const options = yargs
 .usage("Usage: --id <cve-id>")
 .option("id", { alias: "cveId", describe: "CVE ID", type: "string", demandOption: true })
 .argv;

const fetchData = () => {
    const [ cve, year, identifier] = options.cveId.split('-');
    let rawdata = fs.readFileSync(`nvdcve-1.1-${year}.json`);
    let data = JSON.parse(rawdata);

    const cveItem = data.CVE_Items;
    
    cveItem.forEach(cve => {
        if ( cve.cve.CVE_data_meta.ID === options.cveId) {
            console.log(options.cveId)
            console.log(cve.cve.description.description_data[0].value)
            console.log(cve.impact.baseMetricV3.cvssV3.baseScore + ' ' + cve.impact.baseMetricV3.cvssV3.vectorString )
        }
    });
}

fetchData();
