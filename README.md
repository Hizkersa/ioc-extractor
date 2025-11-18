# IOC Extractor

## Features

- **IOC extraction** from arbitrary text / log files:
  - Public IPv4 addresses
  - Domains (with basic TLD allowlist and heuristics)
  - URLs (`http://` / `https://`)
  - Hashes: **MD5**, **SHA-1**, **SHA-256**

- **Multi log-type workflow** (for reporting/metadata):
  - `--log-type firewall | proxy | email | ids | generic`

- **Multiple output formats**:
  - **CSV** (`type,value`)
  - **JSON** (with metadata)
  - **STIX 2.1** bundle of `indicator` objects

- **Human-readable mini-report**:
  - IOC counts per type
  - Domains by TLD
  - Highlights “more suspicious” TLDs (e.g. `.ru`, `.biz`, `.info`)
  - Quick interpretation section

- **VirusTotal integration (optional)**:
  - Looks up IPs, domains and URLs in **VirusTotal v3 API**
  - Prints basic reputation stats (`malicious`, `suspicious`, `harmless`, `undetected`, ...)

- **Nice terminal output**:
  - Colored sections (when stdout is a TTY)
  - Step-by-step progress messages: `[1/5] Reading file...` etc.

## Project structure

Example layout:

```text
ioc-extractor-python/
├── ioc_extractor.py
├── README.md
├── mis_logs/
│   ├── case01_firewall.log
│   ├── case02_web_proxy.log
│   ├── case03_email_header.log
│   ├── case04_ids_suricata.log
│   └── case05_mixed_text.txt
└── output/
    └── ... (generated CSV/JSON/STIX files)

```

## How to Use:
## 1. Open a terminal and navigate to the project folder:

   ```bash
   cd ~/ioc-extractor-python
```
	## 2.	Place or create a log file inside the folder: mis_logs/
Example (quick test):

echo "Suspicious connection from 45.67.89.10 to http://malware-site.net/payload.exe" > mis_logs/test.txt


	## 3.	Run the tool (examples):
	CSV output:

   ```bash
python3 ioc_extractor.py mis_logs/test.txt --log-type generic -o output/result.csv --format csv --explain
```

	JSON output:

 ```bash
python3 ioc_extractor.py mis_logs/test.txt --log-type generic -o output/result.json --format json
```

	STIX 2.1 output:

 ```bash
python3 ioc_extractor.py mis_logs/test.txt --log-type generic -o output/result_stix.json --format stix

```
	Optional VirusTotal enrichment (requires API key):

 ```bash
export VT_API_KEY="YOUR_API_KEY"
python3 ioc_extractor.py mis_logs/test.txt --log-type generic --vt-enrich --explain

```

	## 4.	Check your extracted IOCs inside the output/ folder.

Output Explained (IOC Results)

When you run the tool, two types of output are generated:

Console Output (Human-Readable)

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

=== Analysis Summary ===
File analyzed : mis_logs/test.txt
Log type      : generic
Total unique IOCs found: 4

Breakdown by type:
  - IP: 1
  - DOMAIN: 1
  - URL: 1
  - MD5: 1
  - SHA1: 0
  - SHA256: 0

[+] IOCs saved to: output/result.csv

```

This allows you to quickly identify whether the log contains elements that may indicate malicious activity, such as suspicious outbound connections, unknown servers, malicious payload delivery URLs, or hash values linked to malware samples.

CSV Output (Structured for SOC / SIEM Processing)

The tool also generates a comma-separated file (.csv) in the output/ folder, which can be used for:

✔ Threat intelligence platforms
✔ SIEM enrichment (Splunk, QRadar, Elastic, Sentinel)
✔ Ticketing systems (Jira, ServiceNow)
✔ Sharing with DFIR teams

Example CSV file (output/result.csv):

type	value
IP	45.67.89.10
DOMAIN	malware-site.net
URL	http://malware-site.net/payload.exe
MD5	d41d8cd98f00b204e9800998ecf8427e

Column definitions:

Column	Description
type	The category of IOC (IP, DOMAIN, URL, MD5, SHA1, SHA256)
value	The extracted IOC found in the provided log file


## Requirements
	•	Python 3.8+
	•	Works on macOS, Linux, and Windows
	•	Optional dependency: requests (only if VirusTotal enrichment feature is used)

## License & Author

This project is released under the MIT License.  
You are free to use, modify and distribute it with attribution.
Created by **Sebastián Fuentes**  
Cyber Security Student
GitHub: @Hizkersa  
