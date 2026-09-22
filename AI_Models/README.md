# AI_Models — Posture Scoring & Risk Prioritization

## Purpose

This module contains the AI/ML components that form the core intelligence of GuardianCTI: detecting anomalous cloud configurations, correlating them with threat intelligence, and prioritizing risk specifically for healthcare compliance impact.

## Planned Models

1. **Misconfiguration Anomaly Detector**
   - Input: cloud configuration snapshots (IAM policies, storage bucket settings, network rules)
   - Approach: unsupervised anomaly detection (Isolation Forest / Autoencoder) to flag deviations from secure baselines

2. **Risk Prioritization / Scoring Model**
   - Input: misconfiguration findings + live threat intel (CVE severity, exploit-in-the-wild indicators) + HIPAA impact weighting
   - Approach: supervised ranking model (e.g., gradient-boosted trees) trained to output a composite risk score

3. **HIPAA Compliance Mapping Classifier**
   - Input: finding type/description
   - Approach: rule-based mapping augmented with an NLP classifier to map findings to specific HIPAA Security Rule clauses

## Planned Folder Structure

```
AI_Models/
├── notebooks/           # EDA and experimentation notebooks
├── training/            # training scripts
├── inference/           # inference/serving scripts
├── saved_models/        # exported model artifacts
├── evaluation/          # metrics scripts (precision/recall, ranking quality)
└── README.md
```

## Tech Stack (proposed)

- Python, Scikit-learn, TensorFlow/PyTorch
- Pandas / NumPy for data prep
- MLflow (optional) for experiment tracking

## Status

Not yet implemented — literature review and model selection in progress.
