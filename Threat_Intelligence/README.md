# Threat_Intelligence — Continuous Threat Feed Ingestion

## Purpose

This module continuously pulls, normalizes, and correlates external threat intelligence with the organization's cloud configuration findings, forming the "continuous threat intelligence" component of GuardianCTI.

## Planned Data Sources

| Source | Type | Use |
|---|---|---|
| NVD / CVE Feed | Vulnerability data | Match against outdated software/services in cloud assets |
| MITRE ATT&CK | TTP framework | Map findings to adversary tactics/techniques |
| AlienVault OTX | Open threat exchange (IOCs) | Correlate live indicators with network/config anomalies |
| AbuseIPDB | Malicious IP reputation | Flag suspicious inbound/outbound traffic patterns |
| Healthcare-specific ISACs (e.g., H-ISAC) | Sector threat reports | Contextualize risk to healthcare-targeted campaigns |

## Responsibilities

- Scheduled ingestion (polling/webhooks) of the above feeds
- Normalization into a common internal schema (see `Database/README.md`)
- Correlation logic: link live threat indicators to specific misconfiguration findings
- Feed freshness/health monitoring (ensuring "continuous" intelligence, not stale snapshots)

## Planned Folder Structure

```
Threat_Intelligence/
├── connectors/          # one module per feed source
├── normalization/        # schema mapping / cleaning
├── correlation/          # matching logic against findings
└── README.md
```

## Status

Not yet implemented — feed selection and API access finalized; ingestion pipeline design in progress.
