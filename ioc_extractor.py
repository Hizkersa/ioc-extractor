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
    import requests # pyright: ignore[reportMissingModuleSource]
except ImportError:
    requests = None  # We will handle this gracefully if VT enrichment is requested.


# Simple color handling (only if output is a terminal)
USE_COLOR = sys.stdout.isatty()

RESET = "\033[0m" if USE_COLOR else ""
COLOR_HEADER = "\033[94m" if USE_COLOR else ""   # blue
COLOR_IP = "\033[91m" if USE_COLOR else ""       # red
COLOR_DOMAIN = "\033[93m" if USE_COLOR else ""   # yellow
COLOR_URL = "\033[96m" if USE_COLOR else ""      # cyan
COLOR_HASH = "\033[95m" if USE_COLOR else ""     # magenta
COLOR_INFO = "\033[92m" if USE_COLOR else ""     # green
COLOR_WARNING = "\033[91m" if USE_COLOR else ""  # red

# Very simple TLD allowlist to reduce false positives
COMMON_TLDS = {
    "com", "net", "org", "ru", "de", "io", "info", "biz", "co",
    "uk", "es", "fr", "it", "nl", "ch", "se", "no", "fi", "pl",
    "cz", "eu", "gov", "edu"
}

# TLDs we will mark as "more suspicious"
SUSPICIOUS_TLDS = {"ru", "cn", "biz", "info"}


def is_public_ip(ip_str: str) -> bool:
    """
    Return True if the IP is valid and public (not private, loopback, etc.).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        ):
            return False
        return True
    except ValueError:
        return False


def is_probable_domain(token: str) -> bool:
    """
    Heuristic filter: consider a token a domain only if:
    - contains at least one dot
    - no slashes
    - TLD is in COMMON_TLDS
    - does not end with common script or file extensions (php, exe, html, js)
    """
    token = token.strip()
    if "/" in token or " " in token:
        return False
    if "." not in token:
        return False

    parts = token.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1].lower()
    if tld not in COMMON_TLDS:
        return False

    bad_extensions = {"php", "exe", "html", "htm", "js", "aspx"}
    if tld in bad_extensions:
        return False

    return True


def extract_iocs(text: str) -> Dict[str, set]:
    """
    Extract IOCs (IPs, domains, URLs, hashes) from the given text.
    This is log-format agnostic: firewall, proxy, email, IDS, etc.
    """
    iocs = {
        "IP": set(),
        "DOMAIN": set(),
        "URL": set(),
        "MD5": set(),
        "SHA1": set(),
        "SHA256": set(),
    }

    # Regex patterns
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
    md5_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b")
    sha1_pattern = re.compile(r"\b[a-fA-F0-9]{40}\b")
    sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # Extract URLs
    for match in url_pattern.findall(text):
        iocs["URL"].add(match)

    # Extract IPs and keep only public ones
    for match in ip_pattern.findall(text):
        if is_public_ip(match):
            iocs["IP"].add(match)

    # Extract hashes
    for match in md5_pattern.findall(text):
        iocs["MD5"].add(match)
    for match in sha1_pattern.findall(text):
        iocs["SHA1"].add(match)
    for match in sha256_pattern.findall(text):
        iocs["SHA256"].add(match)

    # Domain extraction:
    # 1) Take host part from URLs
    for url in iocs["URL"]:
        host = url.split("://", 1)[-1].split("/", 1)[0]
        if is_probable_domain(host):
            iocs["DOMAIN"].add(host)

    # 2) Additional loose domain candidates from text
    candidate_pattern = re.compile(r"\b[\w.-]+\.[\w.-]+\b")
    for token in candidate_pattern.findall(text):
        if is_probable_domain(token):
            iocs["DOMAIN"].add(token)

    return iocs


def print_iocs(iocs: Dict[str, set]):
    """
    Pretty-print all IOCs to the console, grouped by type.
    """
    print()
    # IPs
    print(f"{COLOR_HEADER}[IP]{RESET} ({len(iocs['IP'])})")
    if iocs["IP"]:
        for ip in sorted(iocs["IP"]):
            print(f"  - {COLOR_IP}{ip}{RESET}")
    else:
        print("  (none)")

    # Domains
    print()
    print(f"{COLOR_HEADER}[DOMAIN]{RESET} ({len(iocs['DOMAIN'])})")
    if iocs["DOMAIN"]:
        for d in sorted(iocs["DOMAIN"]):
            print(f"  - {COLOR_DOMAIN}{d}{RESET}")
    else:
        print("  (none)")

    # URLs
    print()
    print(f"{COLOR_HEADER}[URL]{RESET} ({len(iocs['URL'])})")
    if iocs["URL"]:
        for u in sorted(iocs["URL"]):
            print(f"  - {COLOR_URL}{u}{RESET}")
    else:
        print("  (none)")

    # MD5
    print()
    print(f"{COLOR_HEADER}[MD5]{RESET} ({len(iocs['MD5'])})")
    if iocs["MD5"]:
        for h in sorted(iocs["MD5"]):
            print(f"  - {COLOR_HASH}{h}{RESET}")
    else:
        print("  (none)")

    # SHA1
    print()
    print(f"{COLOR_HEADER}[SHA1]{RESET} ({len(iocs['SHA1'])})")
    if iocs["SHA1"]:
        for h in sorted(iocs["SHA1"]):
            print(f"  - {COLOR_HASH}{h}{RESET}")
    else:
        print("  (none)")

    # SHA256
    print()
    print(f"{COLOR_HEADER}[SHA256]{RESET} ({len(iocs['SHA256'])})")
    if iocs["SHA256"]:
        for h in sorted(iocs["SHA256"]):
            print(f"  - {COLOR_HASH}{h}{RESET}")
    else:
        print("  (none)")
    print()


def save_to_csv(iocs: Dict[str, set], output_path: str):
    """
    Save all IOCs into a CSV file with columns: type, value.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for ioc_type, values in iocs.items():
            for value in sorted(values):
                writer.writerow([ioc_type, value])


def to_flat_list(iocs: Dict[str, set]):
    """
    Convert the IOC dict into a flat list of dicts.
    """
    flat = []
    for ioc_type, values in iocs.items():
        for value in sorted(values):
            flat.append({"type": ioc_type, "value": value})
    return flat


def save_to_json(iocs: Dict[str, set], output_path: str, metadata: Dict[str, Any]):
    """
    Save IOCs into a simple JSON structure with metadata.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    data = {
        "tool": "ioc_extractor",
        "version": "1.1",
        "metadata": metadata,
        "iocs": to_flat_list(iocs),
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_stix_indicator(ioc_type: str, value: str) -> Dict[str, Any]:
    """
    Build a minimal STIX 2.1 indicator object for a single IOC.
    """
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    if ioc_type == "IP":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "DOMAIN":
        pattern = f"[domain-name:value = '{value}']"
    elif ioc_type == "URL":
        pattern = f"[url:value = '{value}']"
    elif ioc_type in {"MD5", "SHA1", "SHA256"}:
        hash_name = ioc_type
        pattern = f"[file:hashes.'{hash_name}' = '{value}']"
    else:
        # Fallback: generic pattern
        pattern = f"[observable:value = '{value}']"

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "pattern_type": "stix",
        "pattern": pattern,
        "valid_from": now,
        "labels": ["malicious-activity"],
    }
    return indicator


def save_to_stix(iocs: Dict[str, set], output_path: str, metadata: Dict[str, Any]):
    """
    Save IOCs into a basic STIX 2.1 bundle of indicator objects.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    objects = []
    for ioc_type, values in iocs.items():
        for value in sorted(values):
            objects.append(build_stix_indicator(ioc_type, value))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
        "x_ioc_extractor_metadata": metadata,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def generate_summary(iocs: Dict[str, set]) -> Dict[str, Any]:
    """
    Generate a small summary with useful information for an analyst
    and for explaining the results in a simple way.
    """
    total_iocs = sum(len(v) for v in iocs.values())

    # TLDs of domains found
    tld_counts = {}
    suspicious_domains = []
    for d in iocs["DOMAIN"]:
        parts = d.split(".")
        tld = parts[-1].lower() if len(parts) > 1 else ""
        if tld:
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
            if tld in SUSPICIOUS_TLDS:
                suspicious_domains.append(d)

    summary = {
        "total_iocs": total_iocs,
        "per_type_counts": {k: len(v) for k, v in iocs.items()},
        "tld_counts": tld_counts,
        "suspicious_domains": suspicious_domains,
    }
    return summary


def print_human_summary(file_path: str, summary: Dict[str, Any], log_type: str):
    """
    Print a human-friendly summary, like a mini-report.
    """
    print()
    print(f"{COLOR_INFO}=== Analysis Summary ==={RESET}")
    print(f"File analyzed : {file_path}")
    print(f"Log type      : {log_type}")
    print(f"Total unique IOCs found: {summary['total_iocs']}")
    print()

    print("Breakdown by type:")
    for t, c in summary["per_type_counts"].items():
        print(f"  - {t}: {c}")

    if summary["tld_counts"]:
        print()
        print("Domains by TLD:")
        for tld, count in sorted(summary["tld_counts"].items(), key=lambda x: x[1], reverse=True):
            label = ""
            if tld in SUSPICIOUS_TLDS:
                label = f" {COLOR_WARNING}(often abused in malicious campaigns){RESET}"
            print(f"  - .{tld}: {count}{label}")

    if summary["suspicious_domains"]:
        print()
        print(f"{COLOR_WARNING}More suspicious domains (based on TLD):{RESET}")
        for d in sorted(summary["suspicious_domains"]):
            print(f"  - {d}")

    print()
    print("Quick interpretation:")
    if summary["total_iocs"] == 0:
        print("  No IOCs were detected. The file looks clean, at least with the current rules.")
    else:
        print("  The identified IOCs can be used to:")
        print("    • Block IPs and domains at the firewall or proxy.")
        print("    • Create SIEM rules and alerts for future detections.")
        print("    • Enrich the investigation with OSINT / threat intelligence.")
    print()


# -------- VirusTotal integration (basic) -------- #

def vt_get_headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key}


def vt_encode_url_id(url: str) -> str:
    """
    URL ID in VT v3 is the URL in UTF-8, base64 encoded, without padding.
    """
    b = url.encode("utf-8")
    encoded = base64.urlsafe_b64encode(b).decode("utf-8")
    return encoded.strip("=")


def vt_lookup_ip(ip: str, api_key: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers=vt_get_headers(api_key), timeout=10)
    if r.status_code != 200:
        return {"error": r.status_code}
    return r.json()


def vt_lookup_domain(domain: str, api_key: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = requests.get(url, headers=vt_get_headers(api_key), timeout=10)
    if r.status_code != 200:
        return {"error": r.status_code}
    return r.json()


def vt_lookup_url(url_value: str, api_key: str) -> Dict[str, Any]:
    url_id = vt_encode_url_id(url_value)
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    r = requests.get(url, headers=vt_get_headers(api_key), timeout=10)
    if r.status_code != 200:
        return {"error": r.status_code}
    return r.json()


def vt_extract_reputation(vt_json: Dict[str, Any]) -> Dict[str, int]:
    """
    Extract simple reputation counts from VT JSON (harmless, malicious, suspicious, etc.).
    """
    try:
        stats = vt_json["data"]["attributes"]["last_analysis_stats"]
        return stats
    except Exception:
        return {}


def enrich_with_virustotal(iocs: Dict[str, set], api_key: str, max_lookups: int = 10) -> Dict[str, Any]:
    """
    Enrich a subset of IOCs with VirusTotal reputation.
    For simplicity we focus on IP, DOMAIN and URL.
    """
    if requests is None:
        print(f"{COLOR_WARNING}[!] 'requests' library is not installed. VT enrichment skipped.{RESET}")
        return {}

    results = {
        "IP": {},
        "DOMAIN": {},
        "URL": {},
    }

    # Simple rate limitation: we only look up a limited number of IOCs
    to_lookup_ips = list(sorted(iocs["IP"]))[:max_lookups]
    to_lookup_domains = list(sorted(iocs["DOMAIN"]))[:max_lookups]
    to_lookup_urls = list(sorted(iocs["URL"]))[:max_lookups]

    print(f"{COLOR_INFO}[*] VirusTotal enrichment: up to {max_lookups} per type (IP/DOMAIN/URL).{RESET}")

    for ip in to_lookup_ips:
        print(f"{COLOR_INFO}    - Looking up IP in VT: {ip}{RESET}")
        vt_json = vt_lookup_ip(ip, api_key)
        results["IP"][ip] = vt_extract_reputation(vt_json)

    for dom in to_lookup_domains:
        print(f"{COLOR_INFO}    - Looking up DOMAIN in VT: {dom}{RESET}")
        vt_json = vt_lookup_domain(dom, api_key)
        results["DOMAIN"][dom] = vt_extract_reputation(vt_json)

    for url_value in to_lookup_urls:
        print(f"{COLOR_INFO}    - Looking up URL in VT: {url_value}{RESET}")
        vt_json = vt_lookup_url(url_value, api_key)
        results["URL"][url_value] = vt_extract_reputation(vt_json)

    return results


def print_vt_summary(vt_results: Dict[str, Any]):
    """
    Print a short human-readable summary of VirusTotal enrichment.
    """
    if not vt_results:
        return

    print()
    print(f"{COLOR_INFO}=== VirusTotal Enrichment Summary ==={RESET}")
    for ioc_type in ["IP", "DOMAIN", "URL"]:
        entries = vt_results.get(ioc_type, {})
        if not entries:
            continue
        print(f"\n{ioc_type} indicators:")
        for value, stats in entries.items():
            if not stats:
                print(f"  - {value}: (no stats or error)")
            else:
                line_parts = [f"{k}={v}" for k, v in stats.items()]
                line = ", ".join(line_parts)
                print(f"  - {value}: {line}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Simple IOC extractor for DFIR / SOC use cases."
    )
    parser.add_argument("input_file", help="Path to the log or text file")

    parser.add_argument(
        "--log-type",
        choices=["generic", "firewall", "proxy", "email", "ids"],
        default="generic",
        help="Type of log being analyzed (for reporting/metadata purposes).",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to output file (CSV / JSON / STIX, see --format).",
        default=None,
    )

    parser.add_argument(
        "--format",
        choices=["csv", "json", "stix"],
        default="csv",
        help="Output format when using --output (default: csv).",
    )

    parser.add_argument(
        "--explain",
        action="store_true",
        help="Show a human-readable summary (mini-report) at the end.",
    )

    parser.add_argument(
        "--vt-enrich",
        action="store_true",
        help="Enrich IPs, domains and URLs with VirusTotal (requires VT_API_KEY env variable).",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[!] File does not exist: {args.input_file}")
        sys.exit(1)

    # Step-by-step messages
    print(f"{COLOR_INFO}[1/5] Reading file...{RESET}")
    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    print(f"{COLOR_INFO}[2/5] Extracting IOCs from content...{RESET}")
    iocs = extract_iocs(text)

    print(f"{COLOR_INFO}[3/5] Printing detected IOCs...{RESET}")
    print_iocs(iocs)

    vt_results = {}
    if args.vt_enrich:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            print(f"{COLOR_WARNING}[!] VT_API_KEY environment variable not set. Skipping VirusTotal enrichment.{RESET}")
        else:
            print(f"{COLOR_INFO}[4/5] Enriching IOCs with VirusTotal...{RESET}")
            vt_results = enrich_with_virustotal(iocs, api_key=api_key, max_lookups=10)
            print_vt_summary(vt_results)

    if args.output:
        metadata = {
            "input_file": args.input_file,
            "log_type": args.log_type,
        }

        print(f"{COLOR_INFO}[5/5] Saving IOCs to output file ({args.format})...{RESET}")
        if args.format == "csv":
            save_to_csv(iocs, args.output)
        elif args.format == "json":
            save_to_json(iocs, args.output, metadata)
        elif args.format == "stix":
            save_to_stix(iocs, args.output, metadata)

        print(f"[+] IOCs saved to: {args.output}")

    if args.explain:
        summary = generate_summary(iocs)
        print_human_summary(args.input_file, summary, args.log_type)


if __name__ == "__main__":
    main()
