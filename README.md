# GuardianCTI

AI-based cloud security posture assessment for healthcare cloud environments,
using continuous threat intelligence.

BCSE355L Cloud Architecture Design · VIT Vellore
Arun Prakash S (24BIT0551) · R Saharsh Krishna (24BIT0521) · Kamalnayak P (24BIT0367)
Guide: Dr. Priya V

---

## What it does

Reads the configuration of a live AWS account, checks it against a catalogue of
19 healthcare-relevant security controls, enriches each failure with live threat
intelligence, ranks the results with two machine learning models, and reports a
posture score with the exact remediation for every finding.

The design question it answers: given 40 open misconfigurations and one afternoon,
which three should a hospital's administrator fix first? A static CIS scanner
answers that with fixed weights. GuardianCTI answers it with fixed weights *plus*
what is currently being exploited in the wild, *plus* whether the affected
resource holds PHI, *plus* whether the finding is unusual for this account.

## Run it in five minutes

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m guardian.ai_model                            # train, prints accuracy + feature importance
python -m guardian.pipeline --offline                  # full run on synthetic account state
```

Then open `dashboard/index.html` in a browser.

Against a real AWS account, drop `--offline` after exporting Learner Lab
credentials (Canvas → **AWS Details** → copy all three values):

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
python -m guardian.pipeline --region us-east-1 -v
```

## Repository layout

```
guardian/checks.py      19 controls, each mapped to HIPAA / CIS / NIST / ATT&CK
guardian/collector.py   boto3 collectors: S3, EC2, IAM, RDS, CloudTrail, KMS, Lambda
guardian/cti.py         CISA KEV + NVD + ATT&CK feeds, cached, with offline fallback
guardian/scoring.py     likelihood x impact risk model, posture score per control family
guardian/ai_model.py    RandomForest priority classifier + IsolationForest anomaly detector
guardian/pipeline.py    orchestrator, writes out/findings.json and dashboard/data.js
lambda_handler.py       scheduled AWS Lambda entry point, S3 snapshots and SNS alerts
infra/target_stack.yaml CloudFormation for the deliberately misconfigured target workload
dashboard/index.html    single-file dashboard, no build step
```

## How the pieces map to the proposal document

| Document section | Implementation |
|---|---|
| 8.1 Cloud resource monitoring | `lambda_handler.py` on an EventBridge 6-hour schedule |
| 8.2 Configuration data collection | `guardian/collector.py` |
| 8.3 Continuous threat intelligence | `guardian/cti.py` — CISA KEV, NVD, MITRE ATT&CK |
| 8.4 Preprocessing and features | `guardian/ai_model.featurise` — 16-dimension vector |
| 8.5 AI-based risk analysis | `guardian/ai_model.py` — RandomForest + IsolationForest |
| 8.6 Posture assessment | `guardian/scoring.py` |
| 8.7 Recommendation engine | `remediation` field per control, ordered by `final_rank` |
| 8.8 Security dashboard | `dashboard/index.html` |

### Deviations from the proposal, and why

Record these in the report; examiners reward a justified change more than a
stack list that was never built.

- **MongoDB → JSON snapshots in S3, DynamoDB optional.** The AWS Academy Learner
  Lab cannot run a managed MongoDB, and the finding volume is in the hundreds,
  not millions. Document storage buys nothing here.
- **TensorFlow → scikit-learn.** The feature space is 16 dimensions and the
  training set is thousands of rows. A deep network on that data would be a
  worse model and a harder defence in a viva.
- **Grafana / Power BI → single-file dashboard.** No server to keep running
  inside a four-hour lab session, and it deploys as a static S3 website.
- **VirusTotal / OpenCTI → CISA KEV + NVD.** KEV is the authoritative list of
  vulnerabilities confirmed under active exploitation, needs no API key, and
  maps to service classes rather than file hashes, which is what a posture tool
  actually needs. VirusTotal is a malware reputation service and does not inform
  misconfiguration risk.
- **React + FastAPI → deferred.** Listed as future work. Review-2 material if
  time allows; not the part that earns implementation marks.

## Cost note

The target stack is empty S3 buckets, one security group and one uninvoked
Lambda: effectively zero against the $50 lab budget. Do not add EC2, RDS or NAT
Gateways unless you are demonstrating a specific check, and delete them the same
session. Check the **Used $X of $50** counter in Canvas at the end of every session.

Synthetic data only. Never place real or identifiable patient data in this stack.
