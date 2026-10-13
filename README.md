# GuardianCTI

**AI-based cloud security posture assessment for healthcare cloud environments, driven by continuous threat intelligence.**

BCSE355L Cloud Architecture Design · VIT Vellore · Guide: Dr. Priya V

---

## Problem and solution

Healthcare organisations keep Electronic Health Records, imaging and telemedicine data on cloud platforms. A public storage bucket, an open port or an unencrypted database is one of the most common causes of a real-world breach, and periodic static audits cannot keep up with how quickly both cloud configurations and attacker priorities change.

GuardianCTI reads the configuration of a live AWS account, checks it against a catalogue of **27 healthcare-relevant security controls**, enriches each failure with live threat intelligence, ranks the results with machine learning, and reports a posture score with the exact remediation for every finding. It never reads or stores patient data.

The design question it answers: given a dozen open misconfigurations and one afternoon, which should a hospital administrator fix first? A static CIS scanner answers with fixed weights. GuardianCTI answers with fixed weights *plus* what is currently being exploited in the wild, *plus* whether the affected resource holds PHI, *plus* whether the finding is unusual for this account.

## Architecture

![GuardianCTI architecture](Architecture/architecture.png)

A five-stage pipeline; each stage is an independently runnable Python module:

1. **Collector** reads live configuration (read-only) from S3, EC2, IAM, RDS, CloudTrail, KMS and Lambda via boto3.
2. **Control catalogue** holds 27 checks, each mapped to HIPAA, CIS, NIST and MITRE ATT&CK.
3. **Threat intelligence** pulls the CISA KEV catalogue and NVD and turns exploitation volume into a per-service threat-pressure multiplier.
4. **Scoring engine** computes `risk = likelihood × impact`, scaled by threat pressure, exposure and PHI weight, and rolls findings up into an overall and per-family posture score (0–100).
5. **AI layer** runs two independent models (see below), then the **dashboard** presents the result.

## Features

- **Live CTI feed.** CISA KEV (1,717 entries at the last fetch) and NVD, converted into per-service threat pressure (IAM, EC2, RDS, KMS, S3, CloudTrail). The same misconfiguration is ranked differently as attacker focus shifts.
- **27 compliance-mapped checks.** Every finding carries HIPAA Security Rule (45 CFR §164.312), CIS AWS Foundations v3.0.0, NIST SP 800-53 Rev. 5 and MITRE ATT&CK references, so it is actionable for both compliance and technical readers.
- **PHI-aware scoring.** Severity is multiplied by whether the affected resource is tagged as holding patient health information.
- **AI-blended ranking.** A RandomForest priority classifier plus an IsolationForest anomaly detector re-rank the formula output (`final_rank`).
- **Medical IoT intrusion model.** A RandomForest trained on the real WUSTL-EHMS-2020 healthcare dataset, with the dataset, model and metrics all stored in Amazon S3.
- **Recommendation engine.** Every finding includes a specific remediation, ordered by rank.
- **Single-file dashboard.** Posture score, trend across assessment runs, per-family scores, threat-intel panel and an expandable findings ledger. No build step.

### The two models

| | Configuration-risk model | Medical IoT intrusion model |
|---|---|---|
| Module | `guardian/ai_model.py` | `guardian/iot_model.py` |
| Algorithms | RandomForest (priority) + IsolationForest (anomaly) | RandomForest |
| Data | Bootstrapped from the project's own risk formula (no public labelled dataset of cloud misconfigurations exists) | WUSTL-EHMS-2020, real captured traffic plus patient biometrics |
| Input | 16-dimension finding feature vector | 36 features (28 network flow + 8 biometric) |
| Output | Priority class, confidence, anomaly score | Normal / attack classification, feature importance |

The two models are matched to two different data realities rather than forcing one dataset or model type to serve both problems.

## Results

![Dashboard](Results/dashboard.png)

### Posture assessment (live AWS Academy Learner Lab account)

Latest run: **91.5 / 100, Grade A**, across **27 checks**: 8 open findings (4 Medium, 4 Low), 6 on PHI-tagged resources, **0 Critical or High**. The dashboard trend covers 14 assessment runs (first 54.9, latest 91.5).

| Control family | Score |
|---|---|
| Audit and integrity | 60.2 |
| Data protection | 89.4 |
| Application | 95.5 |
| Network and host | 100 |

Top of the current ranking:

| Rank score | Check | Resource | Severity |
|---|---|---|---|
| 9.47 | LOG.1 CloudTrail enabled in all regions | account | Medium |
| 8.59 | S3.3 S3 versioning enabled | cf-templates bucket, guardian-ml-data bucket | Medium |
| 4.63 | S3.4 S3 server access logging | four buckets | Low |
| 4.07 | LAMBDA.1 no plaintext secrets in Lambda environment | vit-ehr-ingest | Medium |

Remediation was demonstrated in waves on the deliberately misconfigured target stack (first evaluation, 19-check catalogue):

| Run | Action | Score | Open | Crit+High |
|---|---|---|---|---|
| 1 | Baseline, no remediation | 85.9 (B) | 9 / 23 | 1 |
| 2 | Closed the exposed security group (SSH, MySQL, all-protocol rules) | 91.1 (A) | 7 / 23 | 0 |
| 3 | Enabled S3 versioning on the patient-records bucket | 92.5 (A) | 6 / 23 | 0 |

### Medical IoT intrusion detection (WUSTL-EHMS-2020)

16,318 records (14,272 normal / 2,046 attack), 75/25 stratified split, RandomForest with 300 trees, max depth 14, balanced class weights. Metrics are written to `ids_metrics.json`.

| Metric | Value |
|---|---|
| Accuracy | 90.17% |
| Macro F1 | 0.804 |
| Macro recall | 0.849 |

| Test set (n = 4,080) | Predicted normal | Predicted attack |
|---|---|---|
| Actual normal | 3,280 | 288 |
| Actual attack | 113 | 399 |

The strongest predictive signals are packet-timing jitter and load irregularities (`DIntPkt`, `DstJitter`, `SrcLoad`), which matches the timing fingerprint of a man-in-the-middle interception. The original dataset authors (Hady et al., 2020) reported 91.56% with k-nearest-neighbours; this untuned RandomForest is comparable while adding feature-importance explainability and running inside an S3-integrated pipeline.

Six identifier columns (`Flgs`, `SrcAddr`, `DstAddr`, `SrcMac`, `DstMac`, `Label`) are excluded from training to prevent label leakage, since the dataset authors built the label from the source MAC address.

## Tech stack

Python · scikit-learn · boto3 · AWS (S3, EC2, IAM, RDS, CloudTrail, KMS, Lambda, EventBridge, CloudFormation) · CISA KEV and NVD feeds · HTML/JS dashboard

## Quick start

```bash
git clone https://github.com/pkn367/GuardianCTI.git && cd GuardianCTI
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m guardian.ai_model                            # train configuration-risk models
python -m guardian.pipeline --offline                  # full run on synthetic account state
python -m http.server 8000                             # serve the dashboard
```

Open <http://localhost:8000/dashboard/index.html>.

**Against a real AWS account**, drop `--offline` after exporting Learner Lab credentials (Canvas → **AWS Details**, copy all three values):

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
python -m guardian.pipeline --region us-east-1 -v
```

**Medical IoT model.** The dashboard panel shows "not trained yet" until the model has been trained once. With the WUSTL-EHMS-2020 CSV in your S3 bucket (`guardian-ml-data-<account-id>`) and credentials exported:

```bash
python -m guardian.iot_model        # streams the CSV from S3, trains, uploads model + metrics to models/
python -m guardian.pipeline         # re-run so the dashboard picks up the result
```

**Target stack.** Deploy the deliberately misconfigured healthcare workload with `infra/target_stack.yaml` (CloudFormation).

## Project structure

```
guardian/checks.py      27 controls, each mapped to HIPAA / CIS / NIST / ATT&CK
guardian/collector.py   boto3 collectors: S3, EC2, IAM, RDS, CloudTrail, KMS, Lambda
guardian/cti.py         CISA KEV + NVD feeds, cached, with offline fallback
guardian/scoring.py     likelihood x impact risk model, posture score per control family
guardian/ai_model.py    RandomForest priority classifier + IsolationForest anomaly detector
guardian/iot_model.py   RandomForest intrusion detector on WUSTL-EHMS-2020, S3-integrated
guardian/pipeline.py    orchestrator, writes out/findings.json and dashboard/data.js
lambda_handler.py       scheduled AWS Lambda entry point, S3 snapshots and SNS alerts
infra/target_stack.yaml CloudFormation for the deliberately misconfigured target workload
dashboard/index.html    single-file dashboard, no build step
Architecture/           architecture diagram
Results/                dashboard screenshots, metrics, sample output
```

### Target environment

| Resource | Purpose |
|---|---|
| `vit-ehr-patient-records-…` (S3) | Tagged PHI; deliberately under-configured |
| `vit-ehr-medical-imaging-…` (S3) | Hardened control bucket: encrypted, versioned, public access blocked |
| `vit-ehr-app-sg` (security group) | Initially open on SSH, MySQL and all protocols to 0.0.0.0/0 |
| `vit-ehr-ingest` (Lambda) | Deliberately holds a plaintext database password in its environment variables |

Supporting buckets: `guardian-ml-data-…` (dataset, `models/` artefacts) and a CloudFormation templates bucket.

## Mapping to the proposal

| Proposal section | Implementation | Status |
|---|---|---|
| 8.1 Cloud resource monitoring | `lambda_handler.py` on an EventBridge schedule | Written and unit-tested, not yet deployed |
| 8.2 Configuration data collection | `guardian/collector.py` | Complete, verified on real AWS |
| 8.3 Continuous threat intelligence | `guardian/cti.py` (CISA KEV, NVD) | Complete |
| 8.4 Preprocessing and features | `guardian/ai_model.featurise`, IoT preprocessing | Complete |
| 8.5 AI-based risk analysis | `ai_model.py`, `iot_model.py` | Two models operational |
| 8.6 Posture assessment | `guardian/scoring.py` | Complete, before/after verified |
| 8.7 Recommendation engine | `remediation` field per control, ordered by `final_rank` | Complete |
| 8.8 Security dashboard | `dashboard/index.html` | Working; IoT panel wired in |

Overall: approximately **85–88%** complete against the proposal's methodology.

### Deviations from the proposal, and why

- **MongoDB → JSON snapshots in S3.** The Learner Lab has no persistent server and a fixed budget, and finding volume is in the dozens per run. A document store buys nothing here.
- **TensorFlow → scikit-learn.** The feature space is small (up to 36 dimensions); a classical model is more appropriate and more explainable than a deep network at this scale.
- **Grafana / Power BI → single-file dashboard.** No server can run through a four-hour lab session, and a static page deploys directly as an S3 website.
- **VirusTotal / OpenCTI → CISA KEV + NVD.** KEV is the authoritative list of vulnerabilities under active exploitation, needs no API key, and maps to service classes rather than file hashes, which suits misconfiguration risk.
- **AWS Security Hub / GuardDuty → custom detection engine.** Neither is on the Learner Lab's allowed service list.
- **React + FastAPI → deferred** to future work.

## Known limitations

- **IAM policy inspection.** The Learner Lab denies reading certain pre-existing policy versions (VocLab guardrail policies). The collector logs this per policy and continues; it is a lab permission boundary, not a tool defect.
- **Scheduled execution** is written but not yet deployed on EventBridge, so assessments are currently triggered manually.
- **Configuration-risk model training data** is bootstrapped from the project's own risk formula rather than real incident history.
- **Open findings** on the target account (CloudTrail, S3 versioning and logging, Lambda secret) are intentionally left as the next remediation waves.

## Remaining work

- Deploy the scheduled Lambda on an EventBridge rule for continuous assessment.
- Enable CloudTrail on the target account to close the top open finding.
- Retrain the configuration-risk model on real collected findings as runs accumulate.
- Optional: move model training into an AWS SageMaker notebook for fully in-cloud compute.

## Cost note

The target stack is empty S3 buckets, one security group and one uninvoked Lambda: effectively zero against the $50 lab budget. Do not add EC2, RDS or NAT Gateways unless demonstrating a specific check, and delete them the same session. Check the **Used $X of $50** counter in Canvas at the end of every session.

**Synthetic data only.** Never place real or identifiable patient data in this stack.

## Team

| Name | Register number |
|---|---|
| Arun Prakash S | 24BIT0551 |
| R Saharsh Krishna | 24BIT0521 |
| Kamalnayak P | 24BIT0367 |

Guide: Dr. Priya V, Associate Professor Senior, SCORE, VIT Vellore.

## References

1. A. A. Hady, A. Ghubaish, T. Salman, D. Unal and R. Jain, "Intrusion Detection System for Healthcare Systems Using Medical and Network Data: A Comparison Study," *IEEE Access*, vol. 8, pp. 106576–106584, 2020.
2. CISA, Known Exploited Vulnerabilities Catalog. <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
3. NIST National Vulnerability Database. <https://nvd.nist.gov/>
4. MITRE ATT&CK. <https://attack.mitre.org/>
5. CIS AWS Foundations Benchmark v3.0.0; NIST SP 800-53 Rev. 5; HIPAA Security Rule, 45 CFR Part 164 Subpart C.
