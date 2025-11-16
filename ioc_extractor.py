import re
import argparse
import csv
from pathlib import Path

# Regex basicos para IOCs
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
)

DOMAIN_REGEX = re.compile(
    r"\b(?:(?!\d+\.)[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,24})\b"
)

URL_REGEX = re.compile(
    r"\bhttps?://[^\s\"'<>]+"
)

MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(text: str) -> dict:
    """Extrae IOCs de un texto y los devuelve en un diccionario."""
    iocs = {
        "ip": set(IPV4_REGEX.findall(text)),
        "domain": set(DOMAIN_REGEX.findall(text)),
        "url": set(URL_REGEX.findall(text)),
        "md5": set(MD5_REGEX.findall(text)),
        "sha1": set(SHA1_REGEX.findall(text)),
        "sha256": set(SHA256_REGEX.findall(text)),
    }
    return iocs


def print_iocs(iocs: dict) -> None:
    """Imprime los IOCs encontrados de forma legible."""
    for ioc_type, values in iocs.items():
        print(f"\n[{ioc_type.upper()}] ({len(values)})")
        if values:
            for v in sorted(values):
                print(f"  - {v}")
        else:
            print("  (none)")


def write_csv(iocs: dict, output_path: Path) -> None:
    """Escribe los IOCs en un archivo CSV con columnas type,value."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for ioc_type, values in iocs.items():
            for v in sorted(values):
                writer.writerow([ioc_type, v])
    print(f"\n[+] IOCs guardados en: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Simple IOC extractor (IP, domains, URLs, hashes) from text files."
    )
    parser.add_argument(
        "input_file",
        help="Ruta al archivo de texto o log a analizar.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Ruta opcional para guardar los IOCs en CSV (por ejemplo: output/iocs.csv).",
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.is_file():
        print(f"[!] El archivo no existe: {input_path}")
        return

    text = input_path.read_text(encoding="utf-8", errors="ignore")

    print(f"[+] Analizando archivo: {input_path}")
    iocs = extract_iocs(text)

    print_iocs(iocs)

    if args.output:
        output_path = Path(args.output)
        write_csv(iocs, output_path)


if __name__ == "__main__":
    main()