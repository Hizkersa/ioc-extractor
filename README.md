# IOC Extractor – DFIR & SOC Automation Tool  
Advanced IOC extraction with CSV / JSON / STIX output, VirusTotal enrichment and optional Web UI.

---

## Overview

**IOC Extractor** is a lightweight but powerful tool designed for **SOC analysts**, **DFIR responders**, **malware analysts**, and **Cyber Security students**.  
It extracts Indicators of Compromise from logs, enriches them using VirusTotal, and can be used both:

✔ From the **terminal (CLI)**  
✔ As a **local web application (Flask UI)**  

---

## Features

### IOC Extraction
Extracts:
- IPv4 Public IPs
- Domains (TLD-validated)
- URLs
- File Hashes (MD5, SHA1, SHA256)

### Multi-format output
- **CSV** (`type,value`)
- **JSON** (with metadata)
- **STIX 2.1** bundle of Indicator objects

### Human-readable Report (`--explain`)
- Total IOCs
- Breakdown per type
- Domains grouped by TLD
- Highlights suspicious TLDs (`.ru`, `.cn`, `.biz`, `.info`)

### VirusTotal Enrichment (`--vt-enrich`)
- Enrich IPs, Domains, and URLs
- Quick reputation summary
- Based on VirusTotal API v3

### Available log-type metadata
`--log-type generic | firewall | proxy | email | ids | system`

### Optional Web Interface (Flask)
Includes:
- File upload  
- On-screen IOC visualization  
- Download of CSV, JSON, STIX  
- VirusTotal enrichment (optional)  
- Simple and clean HTML interface  

---

## Project Structure

```text
ioc-extractor-python/
├── ioc_extractor.py
├── web_app.py
├── README.md
├── HOW_TO_USE.txt
├── mis_logs/
│   ├── case01_firewall.log
│   ├── case02_proxy.log
│   ├── case03_email.log
│   ├── ...
└── output/
    └── generated files (CSV / JSON / STIX)
```

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
