#!/usr/bin/env python3
import re
import csv
import sys
import os
import ipaddress
import argparse
import json
import uuid
import datetime
import base64
from typing import Dict, Any

try:
    import requests  # pyright: ignore[reportMissingModuleSource]
except ImportError:
    requests = None

# ======== Terminal Colors ======== #
USE_COLOR = sys.stdout.isatty()

RESET = "\033[0m" if USE_COLOR else ""
COLOR_HEADER = "\033[94m" if USE_COLOR else ""   # blue
COLOR_IP = "\033[91m" if USE_COLOR else ""       # red
COLOR_DOMAIN = "\033[93m" if USE_COLOR else ""   # yellow
COLOR_URL = "\033[96m" if USE_COLOR else ""      # cyan
COLOR_HASH = "\033[95m" if USE_COLOR else ""     # magenta
COLOR_INFO = "\033[92m" if USE_COLOR else ""     # green
COLOR_WARNING = "\033[91m" if USE_COLOR else ""  # red

# ======== Domain TLD Filters ======== #
COMMON_TLDS = {
    "com", "net", "org", "ru", "de", "io", "info", "biz", "co",
    "uk", "es", "fr", "it", "nl", "ch", "se", "no", "fi", "pl",
    "cz", "eu", "gov", "edu"
}

SUSPICIOUS_TLDS = {"ru", "cn", "biz", "info"}


# ======== IOC Filtering ======== #
def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False


def is_probable_domain(token: str) -> bool:
    token = token.strip()
    if "/" in token or " " in token or "." not in token:
        return False

    parts = token.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1].lower()
    if tld not in COMMON_TLDS:
        return False

    if tld in {"php", "exe", "html", "htm", "js", "aspx"}:
        return False

    return True


# ======== IOC Extraction ======== #
def extract_iocs(text: str) -> Dict[str, set]:
    iocs = {"IP": set(), "DOMAIN": set(), "URL": set(), "MD5": set(), "SHA1": set(), "SHA256": set()}

    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
    md5_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b")
    sha1_pattern = re.compile(r"\b[a-fA-F0-9]{40}\b")
    sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")

    for match in url_pattern.findall(text):
        iocs["URL"].add(match)

    for match in ip_pattern.findall(text):
        if is_public_ip(match):
            iocs["IP"].add(match)

    for match in md5_pattern.findall(text):
        iocs["MD5"].add(match)
    for match in sha1_pattern.findall(text):
        iocs["SHA1"].add(match)
    for match in sha256_pattern.findall(text):
        iocs["SHA256"].add(match)

    candidate_pattern = re.compile(r"\b[\w.-]+\.[\w.-]+\b")
    for token in candidate_pattern.findall(text):
        if is_probable_domain(token):
            iocs["DOMAIN"].add(token)

    for url in iocs["URL"]:
        host = url.split("://")[-1].split("/")[0]
        if is_probable_domain(host):
            iocs["DOMAIN"].add(host)

    return iocs


# ======== Print IOC Output ======== #
def print_iocs(iocs: Dict[str, set]):
    print()
    for key, color in [("IP", COLOR_IP), ("DOMAIN", COLOR_DOMAIN), ("URL", COLOR_URL),
                       ("MD5", COLOR_HASH), ("SHA1", COLOR_HASH), ("SHA256", COLOR_HASH)]:
        print(f"{COLOR_HEADER}[{key}]{RESET} ({len(iocs[key])})")
        if iocs[key]:
            for item in sorted(iocs[key]):
                print(f"  - {color}{item}{RESET}")
        else:
            print("  (none)")
        print()


# ======== Output Writers ======== #
def save_to_csv(iocs: Dict[str, set], output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for t, values in iocs.items():
            for v in sorted(values):
                writer.writerow([t, v])


def to_flat_list(iocs: Dict[str, set]):
    return [{"type": t, "value": v} for t in iocs for v in sorted(iocs[t])]


def save_to_json(iocs: Dict[str, set], output_path: str, metadata: Dict[str, Any]):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    data = {"tool": "ioc_extractor", "version": "1.2", "metadata": metadata, "iocs": to_flat_list(iocs)}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_stix_indicator(ioc_type: str, value: str) -> Dict[str, Any]:
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    pattern_map = {
        "IP": f"[ipv4-addr:value = '{value}']",
        "DOMAIN": f"[domain-name:value = '{value}']",
        "URL": f"[url:value = '{value}']",
        "MD5": f"[file:hashes.'MD5' = '{value}']",
        "SHA1": f"[file:hashes.'SHA1' = '{value}']",
        "SHA256": f"[file:hashes.'SHA256' = '{value}']",
    }
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "pattern_type": "stix",
        "pattern": pattern_map.get(ioc_type, f"[unknown:value = '{value}']"),
        "valid_from": now,
        "labels": ["malicious-activity"]
    }


def save_to_stix(iocs: Dict[str, set], output_path: str, metadata: Dict[str, Any]):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [build_stix_indicator(t, v) for t in iocs for v in sorted(iocs[t])],
        "metadata": metadata
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


# ======== Summary for Analysts ======== #
def generate_summary(iocs: Dict[str, set]) -> Dict[str, Any]:
    total = sum(len(v) for v in iocs.values())
    tld_counts = {}
    suspicious = []

    for d in iocs["DOMAIN"]:
        tld = d.split(".")[-1].lower()
        if tld:
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
            if tld in SUSPICIOUS_TLDS:
                suspicious.append(d)

    return {
        "total_iocs": total,
        "per_type": {k: len(v) for k, v in iocs.items()},
        "tld_counts": tld_counts,
        "suspicious": suspicious
    }


def print_human_summary(file_path: str, summary: Dict[str, Any], log_type: str):
    print(f"{COLOR_INFO}=== Analysis Summary ==={RESET}")
    print(f"File analyzed : {file_path}")
    print(f"Log type      : {log_type}")
    print(f"Total IOCs    : {summary['total_iocs']}\n")
    for t, c in summary["per_type"].items():
        print(f"  - {t}: {c}")

    if summary["tld_counts"]:
        print("\nDomains by TLD:")
        for tld, c in summary["tld_counts"].items():
            flag = f"{COLOR_WARNING} (suspicious){RESET}" if tld in SUSPICIOUS_TLDS else ""
            print(f"  - .{tld}: {c}{flag}")

    if summary["suspicious"]:
        print(f"\n{COLOR_WARNING}Suspicious domains detected:{RESET}")
        for d in summary["suspicious"]:
            print(f"  - {d}")

    print("\nRecommended next steps:")
    if summary["total_iocs"] > 0:
        print("  • Add to TI/Threat Feed for monitoring")
        print("  • Query in SIEM (Elastic/Splunk/QRadar)")
        print("  • Check for related malware using VT/MISP")
    else:
        print("  • No suspicious IOCs detected\n")


# ======== Log Type Auto-Detection ======== #
def detect_log_type(text: str) -> str:
    lower = text.lower()

    if "suricata" in lower or "snort" in lower or "sid:" in lower:
        return "ids"

    if "received:" in lower and "subject:" in lower and "from:" in lower:
        return "email"

    if ("http" in lower and (" get " in lower or " post " in lower)) or "user-agent" in lower:
        return "proxy"

    if ("deny" in lower or "allow" in lower) and re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b:\d{1,5}", text):
        return "firewall"

    if "sandbox restriction" in lower or "com.apple" in lower or "tccd" in lower:
        return "system"

    return "generic"


def print_log_type_hint(log_type: str):
    print(f"\n{COLOR_INFO}Log type interpretation:{RESET}")
    hints = {
        "firewall": "Tracks blocked/allowed traffic -> useful for C2 detection.",
        "proxy": "Tracks web requests -> useful for spotting malware downloads.",
        "email": "Header analysis -> phishing/spoofing detection.",
        "ids": "Alerts from Snort/Suricata -> MITRE mapping.",
        "system": "System-level logs (macOS/tccd sandbox) -> process/permission anomalies.",
        "generic": "Unknown format -> IOC extraction only.",
    }
    print("  " + hints.get(log_type, "No interpretation available."))


# ======== VirusTotal Integration ======== #
def vt_headers(key: str): return {"x-apikey": key}
def vt_id(url: str): return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def vt_lookup(path: str, key: str):
    if not requests:
        return {"error": "requests not installed"}
    r = requests.get(f"https://www.virustotal.com/api/v3/{path}", headers=vt_headers(key), timeout=10)
    return r.json() if r.status_code == 200 else {"error": r.status_code}


def vt_extract(j: Dict[str, Any]) -> Dict[str, int]:
    try:
        return j["data"]["attributes"]["last_analysis_stats"]
    except:
        return {}


def vt_enrich(iocs: Dict[str, set], key: str, max_items=10) -> Dict[str, Any]:
    results = {"IP": {}, "DOMAIN": {}, "URL": {}}
    print(f"{COLOR_INFO}[*] VirusTotal enrichment enabled{RESET}")

    for ip in list(iocs["IP"])[:max_items]:
        results["IP"][ip] = vt_extract(vt_lookup(f"ip_addresses/{ip}", key))

    for d in list(iocs["DOMAIN"])[:max_items]:
        results["DOMAIN"][d] = vt_extract(vt_lookup(f"domains/{d}", key))

    for u in list(iocs["URL"])[:max_items]:
        results["URL"][u] = vt_extract(vt_lookup(f"urls/{vt_id(u)}", key))

    return results


def print_vt_results(results: Dict[str, Any]):
    if not results:
        return
    print(f"\n{COLOR_INFO}=== VirusTotal Reputation ==={RESET}")
    for t, values in results.items():
        for v, stats in values.items():
            if not stats:
                print(f"  - {v}: no data")
            else:
                info = ", ".join([f"{k}={n}" for k, n in stats.items()])
                print(f"  - {v}: {info}")


# ======== MAIN ENTRY POINT ======== #
def main():
    parser = argparse.ArgumentParser(description="IOC Extraction & Threat Intelligence Tool")

    parser.add_argument("input_file", help="Log or text file to analyze")
    parser.add_argument("--log-type",
                        choices=["auto", "generic", "firewall", "proxy", "email", "ids", "system"],
                        default="auto",
                        help="Log type for context. Use 'auto' for automatic detection.")
    parser.add_argument("-o", "--output", help="Output file path", default=None)
    parser.add_argument("--format", choices=["csv", "json", "stix"], default="csv")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--vt-enrich", action="store_true")

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"{COLOR_WARNING}[!] File not found: {args.input_file}{RESET}")
        sys.exit(1)

    print(f"{COLOR_INFO}[1/5] Reading file...{RESET}")
    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    # Auto or manual log-type
    log_type = detect_log_type(text) if args.log_type == "auto" else args.log_type
    print(f"{COLOR_INFO}[1b] Using log type: {log_type}{RESET}")
    print_log_type_hint(log_type)

    print(f"{COLOR_INFO}[2/5] Extracting IOCs...{RESET}")
    iocs = extract_iocs(text)

    print(f"{COLOR_INFO}[3/5] IOC results:{RESET}")
    print_iocs(iocs)

    vt_results = {}
    if args.vt_enrich:
        key = os.getenv("VT_API_KEY")
        if not key:
            print(f"{COLOR_WARNING}[!] VT_API_KEY not found. Skipping enrichment.{RESET}")
        else:
            print(f"{COLOR_INFO}[4/5] Querying VirusTotal...{RESET}")
            vt_results = vt_enrich(iocs, key)
            print_vt_results(vt_results)

    if args.output:
        metadata = {"input_file": args.input_file, "log_type": log_type}
        print(f"{COLOR_INFO}[5/5] Saving output to {args.output}{RESET}")
        if args.format == "csv":
            save_to_csv(iocs, args.output)
        elif args.format == "json":
            save_to_json(iocs, args.output, metadata)
        elif args.format == "stix":
            save_to_stix(iocs, args.output, metadata)
        print(f"{COLOR_INFO}[+] Done{RESET}")

    if args.explain:
        summary = generate_summary(iocs)
        print_human_summary(args.input_file, summary, log_type)


if __name__ == "__main__":
    main()
    