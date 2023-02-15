# bfalcon
Bash Falcon

## Table of contents
* [General info](#general-info)
* [Requirements](#requirements)
* [Setup](#setup)
* [Roadmap](#roadmap)

## General info
BashFalcon is a tool that is intended to simplify the use of the API of the CrowdStrike Falcon platform.
The choice to write it in Bash, when there are already similar PowerShell or Python tools, is intended to allow easy portability to endpoints that have as few requirements as possible.
    
## Requirements
Project is created with:
* Bash shell
* Curl
* Jq

To maintain as high compatibility as possible between different OSs, some specific tools are not used even though they might simplify the code structure. One example is readarray, which is not used because it is not available on the macOS platform.
    
## Setup
To execute BashFalcon, a valid API client must have been created in the CrowdStrike Falcon console. Once you have it, just put the bfalcon.sh file and launch it passing the mandatory arguments:
* API Client ID
* API Secret
* CrowdStrike Cloud (it could be EU-1, US-1 or US-2)

```
$ ./bfalcon-rev1.sh <Client ID> <Secret> <CrowdStrike Cloud>
```

## Roadmap
* Get list of files currently stored on Cloud (feasibility analysis in progress).
* Multi-CID support for Oauth2 API authentication.
* Send API result to LogScale instance (work in progress).
* Implement a better menu structure.
* File upload to CrowdStrike Cloud for further QuickScan and/or Sandbox analysis.
* Get IOCs from CrowdStrike Threat Intel.
* Get IOCs related to Sandbox report.
* Get information about QuickScan and Sandbox quota.