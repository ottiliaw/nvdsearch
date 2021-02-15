# nvdsearch

![tool screenshot](/images/screenshot.png)

This command line tool fetches vulnerability information from the National Vulnerability
Database [(NVD)](https://nvd.nist.gov/vuln/data-feeds#JSON_FEED) based on CVE IDs, and displays the vulnerability description and it's score.

CVSSV3 is used for the severity base score, unless the vulnerability is older than 2002 in which case CVSSV2 is used.


| Functionality                         |   |
|---------------------------------------|---|
| Consume input through command line    | ✔️ |
| Fetch correct zipped JSON             | ✔️ |
| Unzip JSON                            | ✔️ |
| Read the correct data                 | ✔️ |
| Print data in a easily consumable way | ✔️ |
---------------------------------------

### Fetching Data:

When developing this, a decision had to be made between of caching the pulled data locally, or to fetch fresh data every time. There's a trade-off between storage space and time/network traffic, and it depends on the usage frequency of the tool. For this tool, the decision was to fetch and store the data locally, as the files were fairly small, but to have a flag for the user to clear the cache whenever needed. 

*If the user is looking for the latest CVE IDs, then running with the --clear-cache flag is advised, as that will always fetch the most up to date data.*

### Validation:

The tool will only allow CVE IDs that match this regex
> CVE-[0-9]{4}-[0-9]{4,7}

and that are newer than 1999, as that is the data range avaliable.

### Diagram:

![Flow](/images/diagram.png)

--------------------

### Install script:
Pull repo and cd into project folder.

>npm install -g .

>nvdsearch --id [CVE-ID]

### Usage:


Options:
  
  --help  (Show help)
  
  --version      (Show version number)                                   
  
  --clear-cache  (Removes all previously downloaded files, both zipped and unzipped)                                      

  --id, --cveId  (ID to search for)

