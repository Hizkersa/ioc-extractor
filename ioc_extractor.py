#!/usr/bin/env python3
import re
import csv
import sys
import os
import ipaddress
import argparse

# Simple color handling (only if output is a terminal)
USE_COLOR = sys.stdout.isatty()

RESET = "\033[0m" if USE_COLOR else ""
COLOR_HEADER = "\033[94m" if USE_COLOR else ""   # blue
COLOR_IP = "\033[91m" if USE_COLOR else ""       # red
COLOR_DOMAIN = "\033[93m" if USE_COLOR else ""   # yellow
COLOR_URL = "\033[96m" if USE_COLOR else ""      # cyan
COLOR_HASH = "\033[95m" if USE_COLOR else ""     # magenta

# Very simple TLD allowlist to reduce false positives
COMMON_TLDS = {
    "com", "net", "org", "ru", "de", "io", "info", "biz", "co",
    "uk", "es", "fr", "it", "nl", "ch", "se", "no", "fi", "pl",
    "cz", "eu", "gov", "edu"
}


def is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is valid and public (not private, loopback, etc.)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
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


def extract_iocs(text: str):
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
    # 1) take host part from URLs
    for url in iocs["URL"]:
        host = url.split("://", 1)[-1].split("/", 1)[0]
        if is_probable_domain(host):
            iocs["DOMAIN"].add(host)

    # 2) additional loose domain candidates from text
    #    (tokens with dots that might be domains)
    candidate_pattern = re.compile(r"\b[\w.-]+\.[\w.-]+\b")
    for token in candidate_pattern.findall(text):
        if is_probable_domain(token):
            iocs["DOMAIN"].add(token)

    return iocs


def print_iocs(iocs: dict):
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


def save_to_csv(iocs: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for ioc_type, values in iocs.items():
            for value in sorted(values):
                writer.writerow([ioc_type, value])


def main():
    parser = argparse.ArgumentParser(
        description="Simple IOC extractor for DFIR / SOC use cases."
    )
    parser.add_argument("input_file", help="Path to the log or text file")
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to CSV output file (for example: output/iocs.csv)",
        default=None,
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[!] El archivo no existe: {args.input_file}")
        sys.exit(1)

    print(f"[+] Analizando archivo: {args.input_file}")

    with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    iocs = extract_iocs(text)
    print_iocs(iocs)

    if args.output:
        save_to_csv(iocs, args.output)
        print(f"[+] IOCs guardados en: {args.output}")


if __name__ == "__main__":
    main()
    