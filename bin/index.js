#!/usr/bin/env node
const yargs = require("yargs");
const fetch = require('node-fetch');
const unzip = require('unzipper');
const {pipeline} = require('stream');
const {promisify} = require('util');
const fs = require('fs');


const url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'

const options = yargs
 .usage("Usage: --id <cve-id>")
 .option("id", { alias: "cveId", describe: "CVE ID", type: "string", demandOption: true })
 .argv;

const cveId = options.cveId;

async function readPrintdata(cveId){ 
    const JSONfile = await getFileData(cveId)
    const text = await consumeData(JSONfile);
    console.log(text)
}


async function getFileData(cveId){
    const streamPipeline = promisify(pipeline);
    const [ cve, year, identifier] = cveId.split('-');

    const response = await fetch(url+`${year}.json.zip`);

    if (!response.ok) throw new Error(`Error! Unexpected response ${response.statusText}`);

    await streamPipeline(response.body, fs.createWriteStream(`./data_store/zip/nvdcve-1.1-${year}.json.zip`));

    await new Promise((resolve, reject) => { fs.createReadStream(`./data_store/zip/nvdcve-1.1-${year}.json.zip`)
    .pipe(unzip.Extract({ path: `./data_store/unzip` }))
    .on('close', () => resolve())
    .on('error', (error) => reject(error))
    })

    return `./data_store/unzip/nvdcve-1.1-${year}.json`
}

async function consumeData(JSONfile){ 
    let rawdata = fs.readFileSync(JSONfile);
    let parsedJSON = JSON.parse(rawdata);
    const cveItem = parsedJSON.CVE_Items;

    let text = {};
    cveItem.forEach(cve => {
        if (cve.cve.CVE_data_meta.ID === options.cveId) {
            text.cveID = options.cveId;
            text.description = cve.cve.description.description_data[0].value
            text.impact = cve.impact.baseMetricV3.cvssV3.baseScore + ' ' + cve.impact.baseMetricV3.cvssV3.vectorString
        }
    });
    return text;
}

readPrintdata(cveId);


