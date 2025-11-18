#!/usr/bin/env python3
"""
Local Web UI for IOC Extractor

Features:
- Upload log file and analyze IOCs via browser
- Auto / manual log-type selection
- Dark-style UI
- IOC table + human summary
- Optional VirusTotal enrichment (with simple caching)
- Optional Shodan enrichment for IPs (with simple caching)
- Optional download of CSV / JSON / STIX 2.1 bundle
"""

from flask import Flask, request, render_template_string, send_from_directory
import os
import json
import uuid
import datetime
from typing import Dict, Any

# Optional HTTP client (for VT and Shodan)
try:
    import requests  # type: ignore
except ImportError:
    requests = None

# Import core logic from your CLI tool
from ioc_extractor import (
    extract_iocs,
    detect_log_type,
    generate_summary,
)

# ---- Basic config ----
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "web_output"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Simple TLD list for risk & summary
SUSPICIOUS_TLDS = {"ru", "cn", "biz", "info"}

# Caches for VT and Shodan
VT_CACHE: Dict[str, Dict[str, Any]] = {}
SHODAN_CACHE: Dict[str, Dict[str, Any]] = {}


# ========== HTML TEMPLATE (Dark-ish UI) ========== #
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IOC Extractor - Web UI</title>
  <style>
    :root {
      color-scheme: dark;
    }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0b1015;
      color: #e5e9f0;
      margin: 0;
      padding: 0;
    }
    header {
      padding: 20px;
      background: #111822;
      border-bottom: 1px solid #1f2933;
    }
    h1 {
      margin: 0 0 5px 0;
      font-size: 24px;
    }
    .subtitle {
      font-size: 13px;
      color: #9ca3af;
    }
    main {
      padding: 20px;
      max-width: 1100px;
      margin: 0 auto;
    }
    .box {
      border: 1px solid #1f2933;
      background: #111827;
      border-radius: 10px;
      padding: 16px 18px;
      margin-bottom: 20px;
    }
    label {
      display: block;
      margin-top: 10px;
      font-size: 14px;
    }
    select, input[type="file"], button {
      margin-top: 4px;
      padding: 6px 8px;
      border-radius: 6px;
      border: 1px solid #374151;
      background: #020617;
      color: #e5e9f0;
      font-size: 13px;
    }
    button {
      cursor: pointer;
      background: #2563eb;
      border-color: #2563eb;
      margin-top: 15px;
    }
    button:hover {
      background: #1d4ed8;
    }
    input[type="checkbox"] {
      margin-right: 6px;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 10px;
      font-size: 13px;
    }
    th, td {
      border: 1px solid #1f2933;
      padding: 6px 8px;
    }
    th {
      background: #020617;
    }
    .summary {
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      background: #020617;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid #1f2933;
      font-size: 12px;
    }
    .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      background: #111827;
      border: 1px solid #374151;
      margin-right: 6px;
      margin-bottom: 4px;
    }
    .tag-low { border-color: #10b981; color: #6ee7b7; }
    .tag-medium { border-color: #f59e0b; color: #fbbf24; }
    .tag-high { border-color: #ef4444; color: #fecaca; }
    .tag-critical { border-color: #b91c1c; color: #fecaca; }
    .download-link {
      margin-top: 8px;
      font-size: 13px;
    }
    .download-link a {
      color: #60a5fa;
      text-decoration: none;
    }
    .download-link a:hover {
      text-decoration: underline;
    }
    .section-title {
      margin-top: 0;
      margin-bottom: 8px;
      font-size: 18px;
    }
    .small {
      font-size: 12px;
      color: #9ca3af;
    }
  </style>
</head>
<body>
  <header>
    <h1>IOC Extractor - Local Web Interface</h1>
    <div class="subtitle">Upload logs, extract IOCs, enrich with VirusTotal / Shodan, and export results for SOC / DFIR workflows.</div>
  </header>
  <main>

    <div class="box">
      <form method="post" enctype="multipart/form-data">
        <h2 class="section-title">Analyze log file</h2>

        <label>Log file to analyze:</label>
        <input type="file" name="logfile" required>

        <label>Log type:</label>
        <select name="log_type">
          <option value="auto" {% if chosen_log_type == 'auto' %}selected{% endif %}>auto (detect)</option>
          <option value="generic" {% if chosen_log_type == 'generic' %}selected{% endif %}>generic</option>
          <option value="firewall" {% if chosen_log_type == 'firewall' %}selected{% endif %}>firewall</option>
          <option value="proxy" {% if chosen_log_type == 'proxy' %}selected{% endif %}>proxy</option>
          <option value="email" {% if chosen_log_type == 'email' %}selected{% endif %}>email</option>
          <option value="ids" {% if chosen_log_type == 'ids' %}selected{% endif %}>ids</option>
          <option value="system" {% if chosen_log_type == 'system' %}selected{% endif %}>system</option>
        </select>

        <label>Output format (for download):</label>
        <select name="format">
          <option value="none" {% if chosen_format == 'none' %}selected{% endif %}>no file export (just show results)</option>
          <option value="csv" {% if chosen_format == 'csv' %}selected{% endif %}>CSV</option>
          <option value="json" {% if chosen_format == 'json' %}selected{% endif %}>JSON</option>
          <option value="stix" {% if chosen_format == 'stix' %}selected{% endif %}>STIX 2.1 (JSON)</option>
        </select>

        <label>
          <input type="checkbox" name="vt_enrich" value="1" {% if vt_enabled %}checked{% endif %}>
          Enable VirusTotal enrichment (requires VT_API_KEY env var)
        </label>

        <label>
          <input type="checkbox" name="shodan_enrich" value="1" {% if shodan_enabled %}checked{% endif %}>
          Enable Shodan enrichment for IPs (requires SHODAN_API_KEY env var)
        </label>

        <button type="submit">Analyze</button>
        <div class="small">Note: VirusTotal and Shodan API calls are cached in memory to avoid duplicate lookups.</div>
      </form>
    </div>

    {% if iocs %}
    <div class="box">
      <h2 class="section-title">Risk Overview & Export</h2>
      <p>
        <span class="tag {% if risk_label_class %}{{ risk_label_class }}{% endif %}">
          Risk: {{ risk_label }} ({{ risk_score }}/100)
        </span>
      </p>
      <p class="small">
        This score is based on IOC volume, suspicious TLDs, and (if enabled) VirusTotal / Shodan enrichment.
      </p>

      {% if download_name %}
      <div class="download-link">
        Export file: <a href="/download/{{ download_name }}" target="_blank">{{ download_name }}</a>
        <span class="small">({{ chosen_format | upper }})</span>
      </div>
      {% else %}
      <div class="small">No export file generated (output format set to "none").</div>
      {% endif %}
    </div>

    <div class="box">
      <h2 class="section-title">Extracted IOCs</h2>
      <table>
        <tr><th>Type</th><th>Value</th></tr>
        {% for row in flat_iocs %}
          <tr>
            <td>{{ row.type }}</td>
            <td>{{ row.value }}</td>
          </tr>
        {% endfor %}
      </table>
    </div>

    <div class="box">
      <h2 class="section-title">Summary</h2>
      <div class="summary">{{ summary_text }}</div>
    </div>

    {% if vt_results %}
    <div class="box">
      <h2 class="section-title">VirusTotal Enrichment</h2>
      <div class="small">Simple reputation stats per indicator (malicious / suspicious / harmless / undetected).</div>
      {% for t, values in vt_results.items() %}
        {% if values %}
          <h3>{{ t }} indicators</h3>
          <table>
            <tr><th>Value</th><th>Stats</th></tr>
            {% for val, stats in values.items() %}
              <tr>
                <td>{{ val }}</td>
                <td>
                  {% if stats %}
                    {% for k, v in stats.items() %}
                      {{ k }}={{ v }}{% if not loop.last %}, {% endif %}
                    {% endfor %}
                  {% else %}
                    no data
                  {% endif %}
                </td>
              </tr>
            {% endfor %}
          </table>
        {% endif %}
      {% endfor %}
    </div>
    {% endif %}

    {% if shodan_results %}
    <div class="box">
      <h2 class="section-title">Shodan Enrichment (IP context)</h2>
      <div class="small">Basic exposure data: open ports, organization, country (if available).</div>
      <table>
        <tr><th>IP</th><th>Org</th><th>Country</th><th>Open ports</th></tr>
        {% for ip, info in shodan_results.items() %}
          <tr>
            <td>{{ ip }}</td>
            <td>{{ info.org or '-' }}</td>
            <td>{{ info.country or '-' }}</td>
            <td>
              {% if info.ports %}
                {{ info.ports|join(', ') }}
              {% else %}
                -
              {% endif %}
            </td>
          </tr>
        {% endfor %}
      </table>
    </div>
    {% endif %}

    {% endif %}

  </main>
</body>
</html>
"""


# ========== Helpers ========== #
def flat_iocs_list(iocs: Dict[str, set]):
    flat = []
    for t, values in iocs.items():
        for v in sorted(values):
            flat.append({"type": t, "value": v})
    return flat


def build_stix_indicator(ioc_type: str, value: str) -> Dict[str, Any]:
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    if ioc_type == "IP":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "DOMAIN":
        pattern = f"[domain-name:value = '{value}']"
    elif ioc_type == "URL":
        pattern = f"[url:value = '{value}']"
    elif ioc_type in {"MD5", "SHA1", "SHA256"}:
        pattern = f"[file:hashes.'{ioc_type}' = '{value}']"
    else:
        pattern = f"[unknown:value = '{value}']"

    return {
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


def export_file(iocs: Dict[str, set], output_format: str, original_name: str) -> str:
    """
    Generate CSV / JSON / STIX file in OUTPUT_FOLDER and return filename (relative).
    """
    if output_format == "none":
        return ""

    base = os.path.splitext(os.path.basename(original_name))[0]
    if output_format == "csv":
        filename = f"{base}_iocs_web.csv"
        path = os.path.join(OUTPUT_FOLDER, filename)
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("type,value\n")
            for t, vals in iocs.items():
                for v in sorted(vals):
                    f.write(f"{t},{v}\n")
        return filename

    if output_format == "json":
        filename = f"{base}_iocs_web.json"
        path = os.path.join(OUTPUT_FOLDER, filename)
        data = {
            "tool": "ioc_extractor_web",
            "version": "1.0",
            "metadata": {"source_file": original_name},
            "iocs": flat_iocs_list(iocs),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return filename

    if output_format == "stix":
        filename = f"{base}_iocs_web_stix.json"
        path = os.path.join(OUTPUT_FOLDER, filename)
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                build_stix_indicator(t, v) for t, vals in iocs.items() for v in sorted(vals)
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
        return filename

    return ""


# ===== VirusTotal (Web UI, cached) ===== #
def vt_lookup(kind: str, value: str, api_key: str) -> Dict[str, Any]:
    """
    kind: 'ip', 'domain', 'url'
    Caches results in VT_CACHE using key = f"{kind}:{value}"
    """
    cache_key = f"{kind}:{value}"
    if cache_key in VT_CACHE:
        return VT_CACHE[cache_key]

    if not requests:
        VT_CACHE[cache_key] = {}
        return VT_CACHE[cache_key]

    headers = {"x-apikey": api_key}
    if kind == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif kind == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    else:  # url
        encoded = value.encode("utf-8")
        import base64
        vt_id = base64.urlsafe_b64encode(encoded).decode("utf-8").strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            VT_CACHE[cache_key] = {}
        else:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            VT_CACHE[cache_key] = stats
    except Exception:
        VT_CACHE[cache_key] = {}

    return VT_CACHE[cache_key]


def vt_enrich_web(iocs: Dict[str, set], api_key: str, max_items: int = 10) -> Dict[str, Dict[str, Dict[str, int]]]:
    results: Dict[str, Dict[str, Dict[str, int]]] = {"IP": {}, "DOMAIN": {}, "URL": {}}

    for ip in list(iocs.get("IP", []))[:max_items]:
        results["IP"][ip] = vt_lookup("ip", ip, api_key)

    for d in list(iocs.get("DOMAIN", []))[:max_items]:
        results["DOMAIN"][d] = vt_lookup("domain", d, api_key)

    for u in list(iocs.get("URL", []))[:max_items]:
        results["URL"][u] = vt_lookup("url", u, api_key)

    return results


# ===== Shodan (Web UI, cached) ===== #
def shodan_lookup_ip(ip: str, api_key: str) -> Dict[str, Any]:
    if ip in SHODAN_CACHE:
        return SHODAN_CACHE[ip]

    if not requests:
        SHODAN_CACHE[ip] = {}
        return SHODAN_CACHE[ip]

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            SHODAN_CACHE[ip] = {}
        else:
            j = r.json()
            info = {
                "org": j.get("org"),
                "country": j.get("country_code"),
                "ports": j.get("ports", []),
            }
            SHODAN_CACHE[ip] = info
    except Exception:
        SHODAN_CACHE[ip] = {}

    return SHODAN_CACHE[ip]


def shodan_enrich_web(iocs: Dict[str, set], api_key: str, max_items: int = 10) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for ip in list(iocs.get("IP", []))[:max_items]:
        results[ip] = shodan_lookup_ip(ip, api_key)
    return results


# ===== Risk Score ===== #
from typing import Tuple

def compute_risk_score(
    iocs: Dict[str, set],
    summary: Dict[str, Any],
    vt_results: Dict[str, Dict[str, Dict[str, int]]],
    shodan_results: Dict[str, Any],
) -> Tuple[int, str, str]:
    
    """
    Heuristic risk score 0–100 + textual label + CSS class.
    """
    score = 0
    total = summary.get("total_iocs", 0)

    if total == 0:
        return 0, "No IOCs", "tag-low"

    # Base on volume
    score += min(20, total * 3)

    # Suspicious TLDs
    if summary.get("suspicious"):
        score += 20

    # Hash presence (indicates files / payloads)
    if iocs.get("MD5") or iocs.get("SHA1") or iocs.get("SHA256"):
        score += 10

    # VirusTotal malicious counts
    for t, vals in vt_results.items():
        for _, stats in vals.items():
            mal = stats.get("malicious", 0)
            if mal > 0:
                score += min(20, 5 + mal)

    # Shodan: exposed services
    for ip, info in shodan_results.items():
        ports = info.get("ports") or []
        if ports:
            score += min(15, 3 + len(ports))

    # Cap
    score = max(0, min(100, score))

    if score == 0:
        label = "No IOCs"
        css = "tag-low"
    elif score < 30:
        label = "Low"
        css = "tag-low"
    elif score < 60:
        label = "Medium"
        css = "tag-medium"
    elif score < 85:
        label = "High"
        css = "tag-high"
    else:
        label = "Critical"
        css = "tag-critical"

    return score, label, css


# ========== ROUTES ========== #
@app.route("/", methods=["GET", "POST"])
def index():
    iocs = None
    flat = []
    summary_text = ""
    vt_results: Dict[str, Dict[str, Dict[str, int]]] = {}
    shodan_results: Dict[str, Any] = {}
    download_name = ""

    chosen_log_type = "auto"
    chosen_format = "none"
    vt_enabled = False
    shodan_enabled = False
    risk_score = 0
    risk_label = "No IOCs"
    risk_label_class = "tag-low"

    if request.method == "POST":
        file = request.files.get("logfile")
        chosen_log_type = request.form.get("log_type", "auto")
        chosen_format = request.form.get("format", "none")
        vt_enabled = request.form.get("vt_enrich") == "1"
        shodan_enabled = request.form.get("shodan_enrich") == "1"

        if file and file.filename:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()

            # Decide log type
            if chosen_log_type == "auto":
                log_type = detect_log_type(text)
            else:
                log_type = chosen_log_type

            # IOC extraction
            iocs = extract_iocs(text)
            flat = flat_iocs_list(iocs)

            # Summary (string version)
            summary = generate_summary(iocs)
            lines = []
            lines.append(f"File analyzed : {file.filename}")
            lines.append(f"Log type      : {log_type}")
            lines.append(f"Total IOCs    : {summary['total_iocs']}")
            lines.append("")
            lines.append("Breakdown by type:")
            for t, c in summary["per_type"].items():
                lines.append(f"  - {t}: {c}")

            if summary["tld_counts"]:
                lines.append("")
                lines.append("Domains by TLD:")
                for tld, c in summary["tld_counts"].items():
                    flag = " (suspicious)" if tld in SUSPICIOUS_TLDS else ""
                    lines.append(f"  - .{tld}: {c}{flag}")

            if summary["suspicious"]:
                lines.append("")
                lines.append("Suspicious domains:")
                for d in summary["suspicious"]:
                    lines.append(f"  - {d}")

            summary_text = "\n".join(lines)

            # VT enrichment
            if vt_enabled:
                api_key = os.getenv("VT_API_KEY")
                if api_key:
                    vt_results = vt_enrich_web(iocs, api_key)
                else:
                    vt_results = {}

            # Shodan enrichment
            if shodan_enabled:
                shodan_key = os.getenv("SHODAN_API_KEY")
                if shodan_key:
                    shodan_results = shodan_enrich_web(iocs, shodan_key)
                else:
                    shodan_results = {}

            # Risk score
            risk_score, risk_label, risk_label_class = compute_risk_score(
                iocs, summary, vt_results, shodan_results
            )

            # Export file if requested
            download_name = export_file(iocs, chosen_format, file.filename)

    return render_template_string(
        HTML_TEMPLATE,
        iocs=iocs,
        flat_iocs=flat,
        summary_text=summary_text,
        vt_results=vt_results,
        shodan_results=shodan_results,
        download_name=download_name,
        chosen_log_type=chosen_log_type,
        chosen_format=chosen_format,
        vt_enabled=vt_enabled,
        shodan_enabled=shodan_enabled,
        risk_score=risk_score,
        risk_label=risk_label,
        risk_label_class=risk_label_class,
    )


@app.route("/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)


if __name__ == "__main__":
    # debug=True solo para desarrollo local
    app.run(debug=True)
