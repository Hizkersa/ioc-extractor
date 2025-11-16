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
