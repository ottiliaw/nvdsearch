#!/usr/bin/env node
const yargs = require("yargs");
const fetch = require('node-fetch');
const unzip = require('unzipper');
const colors = require('colors');
const {pipeline} = require('stream');
const {promisify} = require('util');
const fs = require('fs');
const fsExtra = require('fs-extra')

const url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'

const options = yargs
 .usage("Usage: --id <cve-id>")
 .options({
    "clear-cache": { describe: "Clears old data. Use flag for the latest CVE updates.", type: "boolean", },
     "id": { alias: "cveId", describe: "CVE ID", type: "string", demandOption: true }
    })
 .check((argv) => {
    const regex = new RegExp("CVE-[0-9]{4}-[0-9]{4,7}");
    if ((regex.test(argv.id)) === false) {
      throw new Error('Error! Invalid CVE-ID format')
    } else if (argv.id.split('-')[1] < 1998 )  {
        throw new Error('Error! No CVE data avaliable before 1999.')
    } else {
        return true
    }
  })
 .argv;


async function getAndPrintCVEInfo(options){ 
    let cveYear = options.cveId.split('-')[1];
    if (cveYear < 2002 ) {
        // this is a bit of a quirk, but all the data pre-2002 is in the 2002 JSON
        cveYear = 2002;
    }
    if (options['clear-cache']) {
        await deleteData()
    }
    const JSONfile = await getData(cveYear)
    const text = await consumeData(JSONfile, cveYear);
    prettyPrint(text);
}

async function getData(year){
    try {
        if (fs.existsSync(`./data_store/unzip/nvdcve-1.1-${year}.json`)) {
            return `./data_store/unzip/nvdcve-1.1-${year}.json`
        
        } else {
            const streamPipeline = promisify(pipeline);

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
      } catch(err) {
        console.error(err)
      }
}

async function consumeData(JSONfile, year){ 
    let rawdata = fs.readFileSync(JSONfile);
    let parsedJSON = JSON.parse(rawdata);
    const cveItem = parsedJSON.CVE_Items;

    let text = {};
    cveItem.forEach(cve => {
        if (cve.cve.CVE_data_meta.ID === options.cveId) {
            text.cveID = options.cveId;
            text.description = cve.cve.description.description_data[0].value
            text.impact = (year < 2002 ) ? cve.impact.baseMetricV3.cvssV3.baseScore : cve.impact.baseMetricV2.cvssV2.baseScore
            text.impactVectorString = (year < 2002 ) ? cve.impact.baseMetricV3.cvssV3.vectorString  : cve.impact.baseMetricV2.cvssV2.vectorString
        }
    });
    return text;
}

async function deleteData(){
    fsExtra.emptyDirSync('./data_store/zip')
    fsExtra.emptyDirSync('./data_store/unzip')
}

function prettyPrint(text){    
    let impact;
    if (text.impact < 4 ) {
        impact = text.impact.toString().green
    } else if (text.impact < 7 ) {
        impact = text.impact.toString().yellow
    } else {
        impact = text.impact.toString().red
    }

    console.log('\n')
    console.log(text.cveID.magenta)
    console.log('-------------'.grey)
    console.log(text.description)
    console.log('-------------'.grey)
    console.log(impact  + ' ' + text.impactVectorString.grey)
    console.log('\n')
}

getAndPrintCVEInfo(options);


