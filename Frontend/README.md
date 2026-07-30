# Frontend — GuardianCTI Dashboard

## Purpose

The frontend provides the security posture dashboard for GuardianCTI: visualizing misconfigurations, threat-intelligence correlations, HIPAA compliance mapping, and prioritized remediation actions for healthcare cloud environments.

## Planned Features

- **Posture Overview Dashboard** — real-time security score, trend over time
- **Findings View** — list of misconfigurations with severity, affected asset, and HIPAA rule mapping
- **Threat Intel Correlation Panel** — shows which live threats/CVEs are linked to each finding
- **Remediation Panel** — AI-suggested fix-it steps, prioritized by risk score
- **Alerts & Notifications** — real-time alerts for newly detected high-risk issues

## Tech Stack (proposed)

- React (with Vite or Next.js)
- Charting: Recharts / Chart.js
- State management: React Query / Redux Toolkit
- Styling: Tailwind CSS

## Folder Structure (to be added as development progresses)

```
Frontend/
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/       # API calls to Backend
│   └── assets/
├── public/
├── package.json
└── README.md
```

## Status

Not yet implemented — planning stage. Update this file as components are built.
