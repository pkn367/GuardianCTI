"""
Security Posture Assessment engine (project document Sections 8.5 and 8.6).

Risk model
----------
    likelihood = base_severity x threat_pressure x exposure_modifier
    impact     = data_sensitivity x axis_weight
    risk       = likelihood x impact            (bounded 0 - 25)

`threat_pressure` comes from the live CTI feeds, which is what separates this
from a static CIS scanner: the same open security group scores differently in a
week when remote-access vulnerabilities dominate the KEV catalogue.

Posture score
-------------
100 minus the sum of open risk, normalised against the worst case where every
check fails on PHI-bearing resources. Reported per control family as well as
overall, because "your account scores 46" is not actionable but "your audit
controls score 12" is.
"""

from __future__ import annotations

from collections import defaultdict

from .checks import CHECKS, band
from .cti import threat_pressure

AXIS_WEIGHT = {"C": 1.0, "I": 0.85, "A": 0.7}

# Evidence patterns that make a finding materially worse than the base case.
EXPOSURE_RULES = {
    "S3.1": lambda ev: 1.4 if ev.get("public_access_block") in ({}, None) else 1.2,
    "EC2.1": lambda ev: 1.0 + 0.15 * len(ev.get("exposed_admin_ports", [])),
    "EC2.2": lambda ev: 1.3 if ev.get("all_protocols_open") else 1.0,
    "IAM.2": lambda ev: 1.0 + min(ev.get("age_days", 0) / 365, 0.5),
    "IAM.4": lambda ev: 1.25 if not ev.get("ever_used", True) else 1.0,
    "RDS.3": lambda ev: 1.3 if ev.get("backup_retention_days", 0) == 0 else 1.0,
    "LOG.1": lambda ev: 1.5 if ev.get("trails", 1) == 0 else 1.1,
}

CONTROL_FAMILY = {
    "S3": "Data protection",
    "RDS": "Data protection",
    "KMS": "Data protection",
    "EC2": "Network and host",
    "IAM": "Identity and access",
    "LOG": "Audit and integrity",
    "LAMBDA": "Application",
}


def _exposure(check_id, evidence):
    rule = EXPOSURE_RULES.get(check_id)
    try:
        return round(min(rule(evidence), 1.6), 3) if rule else 1.0
    except Exception:  # noqa: BLE001 - malformed evidence must not break scoring
        return 1.0


def score_finding(finding, intel):
    meta = CHECKS[finding["check_id"]]
    if finding["status"] != "FAIL":
        finding.update(risk_score=0.0, severity="Passed", likelihood=0.0,
                       impact=0.0, threat_pressure=1.0, exposure=1.0)
        return finding

    pressure = threat_pressure(intel, meta["service"])
    exposure = _exposure(finding["check_id"], finding.get("evidence", {}))
    likelihood = min(meta["base_severity"] * pressure * exposure, 10.0)

    sensitivity = 5.0 if finding.get("phi") else 3.0
    impact = sensitivity * AXIS_WEIGHT[meta["impact_axis"]]

    risk = round(min(likelihood * impact / 2.0, 25.0), 2)

    finding.update(
        risk_score=risk,
        severity=band(risk),
        likelihood=round(likelihood, 2),
        impact=round(impact, 2),
        threat_pressure=pressure,
        exposure=exposure,
        hipaa=meta["hipaa"],
        cis=meta["cis"],
        nist=meta["nist"],
        attack=meta["attack"],
        attack_names=[intel.get("attack_names", {}).get(t, t) for t in meta["attack"]],
        remediation=meta["remediation"],
        family=CONTROL_FAMILY.get(finding["check_id"].split(".")[0], "Other"),
    )
    return finding


def score_all(findings, intel):
    return [score_finding(f, intel) for f in findings]


def posture(findings):
    """Overall and per-family posture, 0 (worst) to 100 (clean)."""
    fails = [f for f in findings if f["status"] == "FAIL"]
    evaluated = [f for f in findings if f["status"] in ("PASS", "FAIL")]
    if not evaluated:
        return {"score": 100.0, "grade": "A", "families": {}, "counts": {},
                "open_findings": 0, "checks_evaluated": 0, "phi_findings": 0}

    # Worst case: every evaluated check fails at its own maximum risk.
    worst = sum(min(CHECKS[f["check_id"]]["base_severity"] * 1.6 * 1.6 * 5.0 *
                    AXIS_WEIGHT[CHECKS[f["check_id"]]["impact_axis"]] / 2.0, 25.0)
                for f in evaluated) or 1.0
    open_risk = sum(f["risk_score"] for f in fails)
    score = round(max(0.0, 100.0 * (1 - open_risk / worst)), 1)

    fam_risk, fam_worst = defaultdict(float), defaultdict(float)
    for f in evaluated:
        meta = CHECKS[f["check_id"]]
        fam = CONTROL_FAMILY.get(f["check_id"].split(".")[0], "Other")
        fam_worst[fam] += min(meta["base_severity"] * 1.6 * 1.6 * 5.0 *
                              AXIS_WEIGHT[meta["impact_axis"]] / 2.0, 25.0)
        if f["status"] == "FAIL":
            fam_risk[fam] += f["risk_score"]

    families = {
        fam: round(max(0.0, 100.0 * (1 - fam_risk[fam] / (fam_worst[fam] or 1))), 1)
        for fam in fam_worst
    }

    counts = defaultdict(int)
    for f in fails:
        counts[f["severity"]] += 1

    return {
        "score": score,
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E",
        "families": families,
        "counts": dict(counts),
        "open_findings": len(fails),
        "checks_evaluated": len(evaluated),
        "phi_findings": sum(1 for f in fails if f.get("phi")),
    }
