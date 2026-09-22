"""
End-to-end orchestrator: collect -> enrich with CTI -> score -> AI rank -> report.

    python -m guardian.pipeline --region us-east-1
    python -m guardian.pipeline --offline        # demo without AWS credentials

Writes out/findings.json (dashboard input) and appends to out/history.json so
the posture score can be plotted across runs. That trend line is the single
most persuasive thing to show in a review: run it against the vulnerable stack,
remediate, run it again, watch the line move.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .ai_model import enrich
from .checks import CHECKS
from .cti import refresh
from .scoring import posture, score_all

OUT = Path(__file__).resolve().parent.parent / "out"
log = logging.getLogger("guardian.pipeline")


def _demo_findings():
    """Synthetic account state, so the pipeline demos with no AWS session."""
    from .collector import _finding
    rows = [
        _finding("S3.1", "vit-ehr-patient-records", "AWS::S3::Bucket", "FAIL", {"public_access_block": {}}, True),
        _finding("S3.2", "vit-ehr-patient-records", "AWS::S3::Bucket", "FAIL", {"algorithm": None}, True),
        _finding("S3.3", "vit-ehr-patient-records", "AWS::S3::Bucket", "FAIL", {"versioning": "Disabled"}, True),
        _finding("S3.4", "vit-ehr-patient-records", "AWS::S3::Bucket", "FAIL", {"access_logging": False}, True),
        _finding("S3.1", "vit-medical-imaging", "AWS::S3::Bucket", "PASS", {"public_access_block": {"BlockPublicAcls": True}}, True),
        _finding("S3.2", "vit-medical-imaging", "AWS::S3::Bucket", "PASS", {"algorithm": "aws:kms"}, True),
        _finding("EC2.1", "sg-0a1b2c3d", "AWS::EC2::SecurityGroup", "FAIL",
                 {"group_name": "ehr-app-sg", "exposed_admin_ports": [{"port": 22, "service": "SSH"},
                                                                     {"port": 3306, "service": "MySQL"}]}, False),
        _finding("EC2.2", "sg-0a1b2c3d", "AWS::EC2::SecurityGroup", "FAIL",
                 {"group_name": "ehr-app-sg", "all_protocols_open": True}, False),
        _finding("EC2.3", "vol-0f9e8d7c", "AWS::EC2::Volume", "FAIL", {"size_gb": 30, "encrypted": False}, True),
        _finding("EC2.4", "i-01234abcd", "AWS::EC2::Instance", "FAIL", {"http_tokens": "optional", "state": "running"}, True),
        _finding("IAM.1", "HospitalAdminPolicy", "AWS::IAM::Policy", "FAIL", {"grants_full_admin": True}, False),
        _finding("IAM.2", "AKIAEXAMPLE0001", "AWS::IAM::AccessKey", "FAIL", {"user": "radiology-svc", "age_days": 412}, False),
        _finding("IAM.3", "radiology-svc", "AWS::IAM::User", "FAIL", {"mfa_devices": 0}, False),
        _finding("IAM.4", "AKIAEXAMPLE0002", "AWS::IAM::AccessKey", "FAIL", {"user": "intern-2024", "idle_days": 260, "ever_used": False}, False),
        _finding("RDS.1", "ehr-postgres", "AWS::RDS::DBInstance", "FAIL", {"publicly_accessible": True, "engine": "postgres"}, True),
        _finding("RDS.2", "ehr-postgres", "AWS::RDS::DBInstance", "FAIL", {"storage_encrypted": False}, True),
        _finding("RDS.3", "ehr-postgres", "AWS::RDS::DBInstance", "FAIL", {"backup_retention_days": 0}, True),
        _finding("LOG.1", "account", "AWS::CloudTrail::Trail", "FAIL", {"trails": 0, "note": "no trail configured"}, False),
        _finding("KMS.1", "3a7b-key", "AWS::KMS::Key", "PASS", {"rotation_enabled": True}, False),
        _finding("LAMBDA.1", "ehr-ingest", "AWS::Lambda::Function", "FAIL",
                 {"suspicious_env_keys": ["DB_PASSWORD"], "runtime": "python3.12"}, False),
    ]
    for r in rows:
        r["region"] = "us-east-1"
    return rows


def run(region="us-east-1", offline=False, use_nvd=False, profile=None):
    OUT.mkdir(parents=True, exist_ok=True)

    if offline:
        log.info("offline mode: using synthetic account state")
        findings = _demo_findings()
    else:
        from .collector import collect_all
        findings = collect_all(region=region, profile=profile)

    technique_ids = {t for c in CHECKS.values() for t in c["attack"]}
    intel = refresh(technique_ids=technique_ids, use_nvd=use_nvd)
    log.info("CTI source=%s kev_total=%s", intel.get("source"), intel.get("kev_total"))

    findings = score_all(findings, intel)
    findings = enrich(findings)

    fails = sorted([f for f in findings if f["status"] == "FAIL"],
                   key=lambda f: -f.get("final_rank", f["risk_score"]))
    summary = posture(findings)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_region": region,
        "posture": summary,
        "cti": {
            "source": intel.get("source"),
            "fetched_at": intel.get("fetched_at"),
            "kev_total": intel.get("kev_total"),
            "kev_matches": intel.get("kev_matches"),
            "pressure": {svc: round(f.get("threat_pressure", 1.0), 3)
                         for svc in {x["service"] for x in fails}
                         for f in fails if f["service"] == svc},
        },
        "findings": fails,
        "passed": [f for f in findings if f["status"] == "PASS"],
    }

    (OUT / "findings.json").write_text(json.dumps(report, indent=2, default=str))

    hist_path = OUT / "history.json"
    history = json.loads(hist_path.read_text()) if hist_path.exists() else []
    history.append({"at": report["generated_at"], "score": summary["score"],
                    "open": summary["open_findings"], "counts": summary["counts"]})
    hist_path.write_text(json.dumps(history[-50:], indent=2))

    # Same payload as a JS assignment, so dashboard/index.html also works when
    # opened directly from the file system (fetch is blocked on file://).
    dash = Path(__file__).resolve().parent.parent / "dashboard"
    dash.mkdir(parents=True, exist_ok=True)
    (dash / "data.js").write_text(
        "window.GUARDIAN_DATA = " + json.dumps(report, default=str) + ";\n"
        "window.GUARDIAN_HISTORY = " + json.dumps(history[-50:], default=str) + ";\n"
    )

    print(f"\nPosture score : {summary['score']}/100  (grade {summary['grade']})")
    print(f"Open findings : {summary['open_findings']} of {summary['checks_evaluated']} checks"
          f"   PHI-bearing: {summary['phi_findings']}")
    print(f"Severity mix  : {summary['counts']}")
    print("\nTop 5 by AI-blended rank")
    for f in fails[:5]:
        flag = " [anomaly]" if f.get("is_anomaly") else ""
        print(f"  {f['final_rank']:6.2f}  {f['check_id']:9s} {f['resource_id'][:34]:34s}"
              f" {f['severity']:8s} ai={f.get('ai_priority')}{flag}")
    print(f"\nWrote {OUT/'findings.json'}")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="GuardianCTI assessment run")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--profile", default=None)
    p.add_argument("--offline", action="store_true", help="synthetic state, no AWS calls")
    p.add_argument("--nvd", action="store_true", help="also query NVD (slow: 6s per keyword without an API key)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    run(region=args.region, offline=args.offline, use_nvd=args.nvd, profile=args.profile)
