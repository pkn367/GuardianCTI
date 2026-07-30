<div align="center">

## GuardianCTI
 
**AI-Based Cloud Security Posture Assessment for Healthcare Organizations using Continuous Threat Intelligence**
 
[![Forks](https://img.shields.io/github/forks/pkn367/GuardianCTI?style=for-the-badge&color=orange)](https://github.com/pkn367/GuardianCTI/network/members)
[![Stars](https://img.shields.io/github/stars/pkn367/GuardianCTI?style=for-the-badge&color=green)](https://github.com/pkn367/GuardianCTI/stargazers)
[![Issues](https://img.shields.io/github/issues/pkn367/GuardianCTI?style=for-the-badge&color=blue)](https://github.com/pkn367/GuardianCTI/issues)
[![Last Commit](https://img.shields.io/github/last-commit/pkn367/GuardianCTI?style=for-the-badge&color=pink)](https://github.com/pkn367/GuardianCTI/commits/main)
 
</div>

 
## Overview
 
[![OVERVIEW](https://img.shields.io/badge/🧠_OVERVIEW-gray?style=for-the-badge)]()
[![AI-DRIVEN CSPM](https://img.shields.io/badge/AI--DRIVEN_CSPM_FOR_HEALTHCARE-8A2BE2?style=for-the-badge)]()
 
GuardianCTI is a research and engineering project that builds an AI-driven Cloud Security Posture Management (CSPM) system tailored to healthcare organizations. Unlike traditional rule-based CSPM tools, HealthShield-AI continuously ingests threat intelligence feeds and correlates them with live cloud configuration data to detect, prioritize, and recommend remediation for security misconfigurations that put Protected Health Information (PHI) and HIPAA compliance at risk.
 
## Problem Statement
 
[![PROBLEM](https://img.shields.io/badge/⚠️_PROBLEM-gray?style=for-the-badge)]()
[![HEALTHCARE CLOUD RISK](https://img.shields.io/badge/HEALTHCARE_CLOUD_ATTACK_SURFACE-D2691E?style=for-the-badge)]()
 
Healthcare organizations are rapidly moving critical workloads — EHR systems, telehealth platforms, medical device data pipelines — to the cloud. This expands the attack surface significantly, while most existing CSPM tools remain static, rule-based, and generic (not tuned to healthcare compliance requirements or real-time threat context).
 
## Objectives
 
[![🎯 OBJECTIVES](https://img.shields.io/badge/🎯_OBJECTIVES-gray?style=for-the-badge)]()
[![HIPAA-AWARE RISK SCORING](https://img.shields.io/badge/HIPAA--AWARE_RISK_SCORING-2E8B57?style=for-the-badge)]()
 
1. Continuously assess the security posture of healthcare cloud assets (storage, IAM, APIs, network configs).
2. Integrate real-time threat intelligence (CVE feeds, MITRE ATT&CK, OSINT indicators) into posture scoring.
3. Build an AI/ML-based risk-prioritization engine that ranks findings by exploitability and HIPAA impact.
4. Provide a dashboard with actionable, prioritized remediation guidance.
5. Evaluate the system against a simulated healthcare cloud environment and baseline CSPM tools.
## Repository Structure
 
[![📁 STRUCTURE](https://img.shields.io/badge/📁_STRUCTURE-gray?style=for-the-badge)]()
[![MODULAR PROJECT LAYOUT](https://img.shields.io/badge/MODULAR_PROJECT_LAYOUT-1E90FF?style=for-the-badge)]()
 
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
 
[![⚙️ TECH STACK](https://img.shields.io/badge/⚙️_TECH_STACK-gray?style=for-the-badge)]()
[![AWS, AI/ML, REACT](https://img.shields.io/badge/AWS%2C_AI%2FML%2C_REACT-DC143C?style=for-the-badge)]()
 
- **Frontend:** React
- **Backend:** Python (FastAPI) / Node.js
- **AI/ML:** Scikit-learn, TensorFlow/PyTorch
- **Database:** PostgreSQL / MongoDB
- **Threat Intel Sources:** NVD/CVE, MITRE ATT&CK, AbuseIPDB, OTX (AlienVault)
- **Cloud Target Environment:** AWS / Azure (sandbox account)

## Team
 
[![👥 TEAM](https://img.shields.io/badge/👥_TEAM-gray?style=for-the-badge)]()
[![PROJECT CONTRIBUTORS](https://img.shields.io/badge/PROJECT_CONTRIBUTORS-FF8C00?style=for-the-badge)]()
 
<div align="center">
<a href="https://github.com/SaharshKrishna06"><img src="https://wsrv.nl/?url=github.com/SaharshKrishna06.png&w=140&h=140&mask=circle&output=png" width="70" height="70" alt="R Saharsh Krishna"/></a>
<a href="https://github.com/pkn367"><img src="https://wsrv.nl/?url=github.com/pkn367.png&w=140&h=140&mask=circle&output=png" width="70" height="70" alt="Kamalnayak"/></a>
<a href="https://github.com/arun1e"><img src="https://wsrv.nl/?url=github.com/arun1e.png&w=140&h=140&mask=circle&output=png" width="70" height="70" alt="Arun Prakash S"/></a>
 
</div>


 
## Statistics
 
[![📊 STATISTICS](https://img.shields.io/badge/📊_STATISTICS-gray?style=for-the-badge)]()
[![REPO ACTIVITY & CONTRIBUTORS](https://img.shields.io/badge/REPO_ACTIVITY_&_CONTRIBUTORS-00CED1?style=for-the-badge)]()
 
<div align="center">
<img src="https://repobeats.axiom.co/api/embed/143a5e3da0371e176d76934e384a8ab183b7c60e.svg" alt="Repobeats analytics"/>
</div>
 
