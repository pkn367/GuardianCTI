# Dataset — GuardianCTI

## Purpose

Contains (or links to) the datasets used to train/evaluate the anomaly detection and risk-prioritization models, and to simulate a healthcare cloud environment for testing.

## Contents

- `Dataset_Links.md` — links to external public datasets used (cloud misconfiguration datasets, CVE archives, healthcare breach reports, synthetic EHR data)
- Local processed/sample datasets (if small enough to version — large raw datasets should stay external and only be linked, not committed)

## Data Categories Needed

1. **Cloud configuration/misconfiguration datasets** — for training the anomaly detector
2. **Vulnerability & threat intelligence datasets** — historical CVE records, exploit databases
3. **Healthcare breach/incident datasets** — for grounding risk-severity weighting in a healthcare context
4. **Synthetic PHI/EHR data** — for safely simulating a healthcare cloud environment without using real patient data


## Status

Dataset sourcing in progress — see `Dataset_Links.md` for current candidate sources.
