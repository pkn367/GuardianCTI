# Database — GuardianCTI Data Layer

## Purpose

Stores cloud configuration snapshots, detected findings, risk scores, threat intelligence records, and historical posture trends for the GuardianCTI system.

## Planned Schema (draft)

- **cloud_assets** — asset id, type, provider, region, owner
- **config_snapshots** — asset_id, timestamp, raw config, config hash
- **findings** — id, asset_id, misconfig_type, severity, hipaa_rule_ref, status, detected_at
- **threat_indicators** — id, source, indicator_type (CVE/IOC), severity, published_at
- **finding_threat_links** — finding_id, threat_indicator_id, correlation_score
- **posture_history** — timestamp, overall_score, org_id

## Tech Stack (proposed)

- **Primary DB:** PostgreSQL (structured findings, relational mapping to compliance rules)
- **Optional:** MongoDB or Elasticsearch for raw/unstructured threat intel storage and fast search

## Folder Structure (to be added as development progresses)

```
Database/
├── migrations/
├── schema.sql
├── seed_data/
└── README.md
```

## Status

Not yet implemented — schema design in progress alongside `Backend` API planning.
