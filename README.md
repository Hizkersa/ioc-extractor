# IOC Extractor (Python)

A simple DFIR (Digital Forensics & Incident Response) tool written in Python to extract Indicators of Compromise (IOCs) from plain text logs.

It helps you quickly pull out:
- IP addresses
- Domains
- URLs
- MD5, SHA1 and SHA256 hashes

Useful for SOC analysts, OSINT work, threat intelligence and incident response.

## Features

- Fast IOC extraction from any text-based log file
- Groups IOCs by type (IP, DOMAIN, URL, MD5, SHA1, SHA256)
- Optional CSV export for further analysis (Excel, SIEM, etc.)
- Minimal dependencies (only Python standard library)
- Simple to run from the command line

## Project structure

```text
ioc-extractor-python/
├── ioc_extractor.py        # Main script
├── samples/
│   └── sample_log.txt      # Example log file
├── output/                 # CSV output folder (created automatically)
└── mis_logs/               # Your own test logs (local tests)

```


## How to Use:
1. Open a terminal and navigate to the project folder:
   cd ~/ioc-extractor-python

2. Place or create a log file inside the folder: mis_logs/
   Example (quick test):
   echo "Suspicious connection from 45.67.89.10 to http://malware-site.net/payload.exe" > mis_logs/test.txt

3. Run the tool:
   python3 ioc_extractor.py mis_logs/test.txt -o output/result.csv

4. Check your extracted IOCs inside the output/ folder.


## Output Explained (IOC Results)

When you run the tool, two types of output are generated:


 ## Console Output (Human-Readable)

The extracted Indicators of Compromise are displayed on screen, grouped by IOC type, for quick visual analysis.
Example:

```text
[IP] (1)
  - 45.67.89.10

[DOMAIN] (1)
  - malware-site.net

[URL] (1)
  - http://malware-site.net/payload.exe

[MD5] (1)
  - d41d8cd98f00b204e9800998ecf8427e

[SHA1] (0)
  (none)

[SHA256] (0)
  (none)

[+] IOCs saved to: output/test_iocs.csv
```

This allows you to quickly identify whether the log contains elements that may indicate malicious activity, such as suspicious outbound connections, unknown servers, or hash values linked to malware samples.

## CSV Output (Structured for SOC / SIEM Processing)

The tool also generates a comma-separated file (.csv) in the output/ folder, which can be used for:

✔ Threat intelligence platforms
✔ SIEM enrichment (Splunk, QRadar, Elastic, Sentinel)
✔ Ticketing systems (Jira, ServiceNow)
✔ Sharing with DFIR teams

Example CSV file (output/test_iocs.csv):

```text
type	value
IP	45.67.89.10
DOMAIN	malware-site.net
URL	http://malware-site.net/payload.exe
MD5	d41d8cd98f00b204e9800998ecf8427e

Column definitions:

Column	Description
type	The category of IOC (IP, DOMAIN, URL, MD5, SHA1, SHA256)
value	The extracted IOC found in the provided log file
```

Interpretation Guide

IOC Type	Meaning	Why It Matters
IP	Remote server used for communication	May indicate C2 (Command & Control) activity
Domain	Hostname used by attacker	Easier to track in DNS logs or threat feeds
URL	Resource path used for delivery	Identifies payloads, phishing links or drop servers
Hash	File fingerprint	Used to check malware fingerprints in VirusTotal, MISP, etc.


## Requirements

- Python 3.8+
- Works on macOS, Linux and Windows
- No additional libraries required (uses Python standard library only)

## License & Author

This project is released under the MIT License.  
You are free to use, modify and distribute it with attribution.
Created by **Sebastián Fuentes**  
Cyber Security Student
GitHub: @Hizkersa  