# GuardianCTI

**AI-Based Cloud Security Posture Assessment for Healthcare Organizations using Continuous Threat Intelligence**

## Overview

GuardianCTI is a research and engineering project that builds an AI-driven Cloud Security Posture Management (CSPM) system tailored to healthcare organizations. Unlike traditional rule-based CSPM tools, GuardianCTI continuously ingests threat intelligence feeds and correlates them with live cloud configuration data to detect, prioritize, and recommend remediation for security misconfigurations that put Protected Health Information (PHI) and HIPAA compliance at risk.

## Problem Statement

Healthcare organizations are rapidly moving critical workloads — EHR systems, telehealth platforms, medical device data pipelines — to the cloud. This expands the attack surface significantly, while most existing CSPM tools remain static, rule-based, and generic (not tuned to healthcare compliance requirements or real-time threat context).

## Objectives

1. Continuously assess the security posture of healthcare cloud assets (storage, IAM, APIs, network configs).
2. Integrate real-time threat intelligence (CVE feeds, MITRE ATT&CK, OSINT indicators) into posture scoring.
3. Build an AI/ML-based risk-prioritization engine that ranks findings by exploitability and HIPAA impact.
4. Provide a dashboard with actionable, prioritized remediation guidance.
5. Evaluate the system against a simulated healthcare cloud environment and baseline CSPM tools.

## Repository Structure

```
GuardianCTI/
├── Documentation/        # Literature survey, research gap, objectives, methodology, proposal
├── Architecture/         # System architecture, framework, and workflow diagrams
├── Frontend/             # Dashboard / UI application
├── Backend/              # APIs, core application logic
├── AI_Models/            # ML/AI models for posture scoring & risk prioritization
├── Database/             # Schemas, migrations, data access layer
├── Threat_Intelligence/  # Threat feed ingestion & correlation modules
├── Dataset/              # Datasets and dataset source links
├── Results/              # Evaluation results, metrics, benchmarks
├── Presentation/         # Slides and demo material
└── Team/                 # Work distribution and individual contributions
```

## Tech Stack (proposed)

- **Frontend:** React
- **Backend:** Python (FastAPI) / Node.js
- **AI/ML:** Scikit-learn, TensorFlow/PyTorch
- **Database:** PostgreSQL / MongoDB
- **Threat Intel Sources:** NVD/CVE, MITRE ATT&CK, AbuseIPDB, OTX (AlienVault)
- **Cloud Target Environment:** AWS / Azure (sandbox account)


## Team

- R Saharsh Krishna - 24BIT0521
- Kamalnayak - 24BIT0367
- Arun Prakash S - 24BIT0551

