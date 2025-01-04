![RealGoVetter](https://github.com/user-attachments/assets/591ed09f-dc57-440f-8690-d9aad1474d20)

# RealGoVetter

- Is a questionable IOC feed becoming synonymous with "false positive"? 
- Are you analyzing a threat actor that spent as much time registering domains as they did collecting ransoms? 
- Did the SOC send you a request to review IPs from seemingly half the internet? 

Look no further!

This is a simple portable GUI Windows program designed to leverage the VirusTotal API to do reputation checks on files, domains, IPs, and URLs in *BULK*. You are only limited by your VirusTotal account's API quota. This is sizeable even with a free account. 

## Features

- Runs as a portable Windows executable without dependencies 
- Has a simple GUI interface
- Accepts .CSV or .TXT files containing IOCs
- Evaluates multiple types of IOCs:
  - File Hashes
  - Domains
  - IP Addresses
  - URLs
- API key storage
- CSV output with detailed analysis results

### Full Bulk IOC Vetting Process

![vettingIOCs](https://github.com/user-attachments/assets/8d0b8e97-0f94-4f08-9224-fe1bb7646771)

### Example Output

![exampleoutput](https://github.com/user-attachments/assets/801d523e-dc94-4ed2-919b-ef66518f244e)

### Saving VirusTotal API Key

![API](https://github.com/user-attachments/assets/93a60e1a-fd6c-4f40-a97f-dd3278087422)

## Requirements

- x64 Windows
- VirusTotal API key (you need at least a free account to access the VirusTotal API)

## Installation

1. Download the latest [release](https://github.com/grepstrength/RealGoVetter/releases).
2. Run the executable.
3. Enter your VirusTotal API key.
4. Start analyzing IOCs.

*The test file used in the gifs above was added to this repo under the "test_file" directory. They were randomly selected IOCs from multiple recent Palo Alto Unit 42 articles.*

## Build From Source
*You will need Go v1.23.4 installed.*
```bash
go install github.com/grepstrength/RealGoVetter@latest
```
Or:
```
git clone https://github.com/grepstrength/RealGoVetter.git
cd RealGoVetter
go build main.go
```
## Usage

1. Launch RealGoVetter. 
    - If stopped by Microsoft Defender Smartscreen, right click on the .EXE > Properties > in the General tab check the "Unblock" option.
    - Relaunch the app.
    - Note: [Click here for the *clean* VirusTotal sandbox submission for the latest v1.0.1 release](https://www.virustotal.com/gui/file/9704a2465febe66710d2d5f3405afd440ecf26f893c4b96473f193bc872d6200). 
2. Enter your VirusTotal API key. 
    - You can optionally save it with the "Save API Key" option.
3. Click "Select IOC File" to choose your input file. The analysis begins as soon as you select the input file.
4. Wait for the analysis to complete.
5. Results will be saved as a .CSV file in the same directory as RealGoVetter.

## Configuration

- The API key will be stored in: `C:\Users\<USERNAME>\AppData\Roaming\RealGoVetter\config.dat`
- Output files are saved in the following format in the same directory as the main .EXE: `results_YYYYMMDDHHMMSS.csv`

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

## Future Plans & Improvements

- Linux support
- Greater input file support
- Support for analyzing defanged network IOCs