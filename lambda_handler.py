"""
AWS Lambda entry point. This is what makes the assessment *continuous*
(project document Section 8.1) rather than something a student runs by hand.

Deploy in the Learner Lab
-------------------------
1. Package:  pip install -r requirements.txt -t build/ && cp -r guardian lambda_handler.py build/
             cd build && zip -r ../guardian.zip . && cd ..
   (scikit-learn is large; if the zip exceeds 250 MB unzipped, set SKIP_AI=1 and
    the function falls back to deterministic scoring only. The AI ranking can
    then run in a SageMaker notebook against the same findings.json.)
2. Create function: runtime python3.12, handler lambda_handler.handler,
   execution role LabRole, timeout 300s, memory 1024 MB.
3. Environment: RESULTS_BUCKET=<your results bucket>, ALERT_TOPIC_ARN=<optional SNS topic>
4. Trigger: EventBridge rule, rate(6 hours).

Each run writes a timestamped snapshot plus latest.json to S3, and publishes an
SNS alert when the posture score drops or a Critical finding appears.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import boto3

RESULTS_BUCKET = os.environ.get("RESULTS_BUCKET")
ALERT_TOPIC = os.environ.get("ALERT_TOPIC_ARN")
REGION = os.environ.get("TARGET_REGION", "us-east-1")
DROP_ALERT = float(os.environ.get("SCORE_DROP_ALERT", "5"))


def handler(event, context):
    from guardian.ai_model import enrich
    from guardian.checks import CHECKS
    from guardian.collector import collect_all
    from guardian.cti import refresh
    from guardian.scoring import posture, score_all

    findings = collect_all(region=REGION)
    intel = refresh(technique_ids={t for c in CHECKS.values() for t in c["attack"]},
                    use_nvd=False)
    findings = score_all(findings, intel)
    if os.environ.get("SKIP_AI") != "1":
        findings = enrich(findings)

    fails = sorted([f for f in findings if f["status"] == "FAIL"],
                   key=lambda f: -f.get("final_rank", f["risk_score"]))
    summary = posture(findings)
    now = datetime.now(timezone.utc)
    report = {"generated_at": now.isoformat(), "account_region": REGION,
              "posture": summary, "cti": {"source": intel.get("source"),
                                          "kev_total": intel.get("kev_total"),
                                          "kev_matches": intel.get("kev_matches"),
                                          "fetched_at": intel.get("fetched_at")},
              "findings": fails}

    previous = None
    if RESULTS_BUCKET:
        s3 = boto3.client("s3")
        try:
            previous = json.loads(s3.get_object(Bucket=RESULTS_BUCKET,
                                                Key="latest.json")["Body"].read())
        except Exception:  # noqa: BLE001 - first run has no previous snapshot
            previous = None
        body = json.dumps(report, default=str).encode()
        key = f"assessments/{now:%Y/%m/%d}/{now:%H%M%S}.json"
        s3.put_object(Bucket=RESULTS_BUCKET, Key=key, Body=body, ContentType="application/json")
        s3.put_object(Bucket=RESULTS_BUCKET, Key="latest.json", Body=body, ContentType="application/json")

    if ALERT_TOPIC:
        reasons = []
        criticals = [f for f in fails if f["severity"] == "Critical"]
        if criticals:
            reasons.append(f"{len(criticals)} critical finding(s)")
        if previous:
            delta = summary["score"] - previous["posture"]["score"]
            if delta <= -DROP_ALERT:
                reasons.append(f"posture dropped {abs(delta):.1f} points to {summary['score']}")
        if reasons:
            top = "\n".join(f"  {f['severity']:8s} {f['check_id']:9s} {f['resource_id']}"
                            for f in fails[:8])
            boto3.client("sns").publish(
                TopicArn=ALERT_TOPIC,
                Subject=f"GuardianCTI: posture {summary['score']}/100 in {REGION}",
                Message=f"Triggered by: {'; '.join(reasons)}\n\n"
                        f"Open findings: {summary['open_findings']} "
                        f"({summary['phi_findings']} on PHI resources)\n\n{top}\n")

    return {"statusCode": 200,
            "body": json.dumps({"score": summary["score"],
                                "open_findings": summary["open_findings"],
                                "counts": summary["counts"]})}
