"""
Continuous Threat Intelligence layer (project document Section 8.3).

Three free feeds, no paid subscription and no API key required to get running:

  CISA KEV   vulnerabilities confirmed to be exploited in the wild, updated
             on working days. This is the feed that makes "continuous" real --
             a check whose technique appears in KEV is not theoretical.
  NVD        CVE severity and CVSS vectors, queried by keyword per service.
  ATT&CK     technique names for the IDs declared in checks.py, so findings
             speak the language the security team already uses.

Output is a per-service "threat pressure" multiplier in the range 1.0 - 1.6
that scoring.py folds into likelihood. A misconfiguration that matches an
actively exploited vulnerability class gets pushed up the queue; the same
misconfiguration in a quiet week does not.

Everything is cached to data/cti_cache.json so a demo works offline.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

log = logging.getLogger("guardian.cti")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json")

CACHE = Path(__file__).resolve().parent.parent / "data" / "cti_cache.json"
CACHE_TTL_HOURS = 12

# Keywords that decide whether a KEV/CVE entry is relevant to one of our services.
SERVICE_KEYWORDS = {
    "s3": ["s3", "object storage", "bucket", "amazon web services"],
    "ec2": ["ec2", "ssh", "openssh", "rdp", "remote desktop", "linux kernel", "windows server"],
    "iam": ["iam", "identity", "authentication", "credential", "privilege escalation", "sso"],
    "rds": ["mysql", "postgresql", "mariadb", "aurora", "database", "sql"],
    "cloudtrail": ["logging", "audit", "siem"],
    "kms": ["encryption", "key management", "tls", "openssl"],
    "lambda": ["serverless", "lambda", "node.js", "python"],
}

# Curated fallback so the pipeline still produces sensible output with no network.
FALLBACK = {
    "kev_matches": {"ec2": 34, "rds": 12, "iam": 9, "lambda": 5, "s3": 2, "kms": 6, "cloudtrail": 0},
    "kev_total": 1180,
    "cve_severity": {"ec2": 8.4, "rds": 7.9, "iam": 8.1, "lambda": 7.2, "s3": 6.5, "kms": 7.0, "cloudtrail": 5.4},
    "attack_names": {},
    "source": "fallback",
}


def _get_json(url, timeout=25, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "GuardianCTI/1.0 (academic project)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_kev():
    data = _get_json(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    matches = {svc: 0 for svc in SERVICE_KEYWORDS}
    for v in vulns:
        blob = f"{v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')} {v.get('shortDescription','')}".lower()
        for svc, words in SERVICE_KEYWORDS.items():
            if any(w in blob for w in words):
                matches[svc] += 1
    log.info("KEV: %d entries, matches %s", len(vulns), matches)
    return matches, len(vulns)


def _fetch_nvd_severity(api_key=None):
    """Mean CVSS base score of recent CVEs per service keyword.

    NVD asks for 6 seconds between anonymous requests. With an API key
    (free, https://nvd.nist.gov/developers/request-an-api-key) it is 0.6s.
    """
    headers = {"User-Agent": "GuardianCTI/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    severity = {}
    for svc, words in SERVICE_KEYWORDS.items():
        try:
            url = f"{NVD_URL}?keywordSearch={urllib.parse.quote(words[0])}&resultsPerPage=40"
            data = _get_json(url, headers=headers)
            scores = []
            for item in data.get("vulnerabilities", []):
                metrics = item["cve"].get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        scores.append(metrics[key][0]["cvssData"]["baseScore"])
                        break
            severity[svc] = round(sum(scores) / len(scores), 2) if scores else 5.0
        except Exception as exc:  # noqa: BLE001 - feed outage must not break the run
            log.warning("NVD query failed for %s: %s", svc, exc)
            severity[svc] = FALLBACK["cve_severity"].get(svc, 5.0)
        time.sleep(0.7 if api_key else 6.2)
    return severity


def _fetch_attack_names(technique_ids):
    try:
        bundle = _get_json(ATTACK_URL, timeout=90)
    except Exception as exc:  # noqa: BLE001
        log.warning("ATT&CK fetch failed: %s", exc)
        return {}
    names = {}
    wanted = set(technique_ids)
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in wanted:
                names[ref["external_id"]] = obj.get("name", "")
    return names


def refresh(technique_ids=(), use_nvd=True, api_key=None, force=False):
    """Fetch all feeds and cache. Returns the intel dict."""
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    if CACHE.exists() and not force:
        age_h = (time.time() - CACHE.stat().st_mtime) / 3600
        if age_h < CACHE_TTL_HOURS:
            log.info("CTI cache is %.1fh old, reusing", age_h)
            return json.loads(CACHE.read_text())

    intel = dict(FALLBACK)
    try:
        matches, total = _fetch_kev()
        intel["kev_matches"], intel["kev_total"], intel["source"] = matches, total, "live"
    except Exception as exc:  # noqa: BLE001
        log.warning("KEV fetch failed, using fallback: %s", exc)

    if use_nvd:
        intel["cve_severity"] = _fetch_nvd_severity(api_key or os.getenv("NVD_API_KEY"))
    if technique_ids:
        intel["attack_names"] = _fetch_attack_names(technique_ids)

    intel["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    CACHE.write_text(json.dumps(intel, indent=2))
    return intel


def threat_pressure(intel, service):
    """Map feed volume onto a 1.0 - 1.6 likelihood multiplier.

    Rationale documented for the report: the share of actively exploited
    vulnerabilities touching this service, scaled by how severe recent CVEs in
    that space have been. Both terms are bounded so a noisy feed cannot make
    every finding critical.
    """
    total = max(intel.get("kev_total", 1), 1)
    share = intel.get("kev_matches", {}).get(service, 0) / total
    exploit_term = min(share * 12, 0.35)              # 0 - 0.35
    sev = intel.get("cve_severity", {}).get(service, 5.0)
    severity_term = max(0.0, (sev - 5.0) / 5.0) * 0.25  # 0 - 0.25
    return round(1.0 + exploit_term + severity_term, 3)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from .checks import CHECKS
    ids = {t for c in CHECKS.values() for t in c["attack"]}
    data = refresh(technique_ids=ids, use_nvd=False, force=True)
    for svc in SERVICE_KEYWORDS:
        print(f"{svc:12s} pressure={threat_pressure(data, svc)}")
