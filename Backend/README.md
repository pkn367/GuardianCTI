# Backend — GuardianCTI Core Services

## Purpose

The backend exposes APIs that tie together cloud configuration data, threat intelligence feeds, and AI model outputs, then serves prioritized findings to the Frontend dashboard.

## Responsibilities

- Authenticate and pull configuration data from cloud provider APIs (AWS Config / Azure Policy)
- Orchestrate calls to the `AI_Models` scoring engine
- Fetch and normalize data from the `Threat_Intelligence` module
- Map findings to HIPAA/HITECH compliance rules
- Persist findings, scores, and history to the `Database` layer
- Expose REST/GraphQL endpoints consumed by the `Frontend`

## Tech Stack (proposed)

- Python (FastAPI) or Node.js (Express)
- Task scheduling: Celery / APScheduler (for continuous posture scans)
- Authentication: OAuth2 / JWT

## Planned API Endpoints (draft)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/posture/score` | Current overall security posture score |
| GET | `/api/findings` | List of misconfigurations with severity & compliance mapping |
| GET | `/api/threats/live` | Current correlated threat intelligence indicators |
| POST | `/api/scan/trigger` | Manually trigger a posture assessment scan |
| GET | `/api/remediation/{finding_id}` | AI-generated remediation suggestion |

## Folder Structure (to be added as development progresses)

```
Backend/
├── app/
│   ├── routes/
│   ├── services/
│   ├── models/         # request/response schemas (not ML models)
│   └── config/
├── tests/
├── requirements.txt
└── README.md
```

## Status

Not yet implemented — planning stage. Update this file as endpoints are built.
