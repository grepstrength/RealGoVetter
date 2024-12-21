# RealGoVetter

Are you analyzing a threat actor that spent as much time registering domains as they did collecting ransoms? 

Did the SOC send you a request to review IPs from seemingly half the internet? 

Look no further!

This is a simple portable GUI Windows program designed to leverage the VirusTotal API to evaluate files, domains, IPs, and URLs in *BULK*. You are only limited by your VirusTotal account's API quota. 

## Features

- Runs as a portable Windows executable 
- Has a simple GUI interface
- Accepts CSV or TXT files containing IOCs
- Evaluates multiple types of IOCs:
  - File Hashes
  - Domains
  - IP Addresses
  - URLs
- Secure API key storage
- CSV output with detailed analysis results

## Requirements

- x64 Windows 
- VirusTotal API key

## Installation

1. Download the latest release.
2. Run the executable.
3. Enter your VirusTotal API key.
4. Start analyzing IOCs.

## Build From Source
```bash
go install github.com/grepstrength/RealGoVetter@latest
```
## Usage

1. Launch RealGoVetter.
2. Enter your VirusTotal API key and click "Save API Key". (Optional)
3. Click "Select IOC File" to choose your input file.
4. Wait for analysis to complete.
5. Results will be saved as CSV in the same directory.

## Configuration

- The API key will be stored in: `C:\Users\<USERNAME>\AppData\Local\RealGoVetter\config.dat`
- Output files are saved in the following format: `results_YYYYMMDDHHMMSS.csv`

## Limitations

- This only works with VirusTotal API keys. 
  - There are currently no plans to offer support for more API keys. 
  - This also means that if you're using a free VT account, you are limited to:
    - 4 lookups / min 
    - 500 lookups / day 
    - 15.5 K lookups / month 
- This only takes .CSV and .TXT files. 
- There is currently no way to process defanged network IOCs. 
  - They will return as "Not Found" in the output .CSV file. 