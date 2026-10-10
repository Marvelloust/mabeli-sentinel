# Feature Completion Matrix — Mabeli Sentinel v2.1

| Area | Implemented behavior |
|---|---|
| Organization | Mabeli Technology throughout application and project documents |
| Backend | Node.js + Express is the central application backend |
| Database | MongoDB/Mongoose persistence for operational, benchmark and isolated test records |
| AI/ML | Python FastAPI service using scikit-learn |
| Ready model | Persisted genuine CICIDS2017-derived offline baseline loads on first startup |
| Automatic upgrade | Background attempt to download/train/promote stronger 20,000-row public baseline |
| Dataset | Bundled verified benchmark fallback + full CICIDS2017 acquisition/retraining support |
| System readiness | API, MongoDB, ML service, model, benchmark, test workspace and live-source checks |
| Benchmark Lab | Genuine labelled CICIDS2017-derived rows processed through Node → ML → MongoDB |
| Test Centre | One-click isolated end-to-end workspace generated from genuine bundled CICIDS2017-derived fixtures |
| Test fixtures | Downloadable benign/PortScan JSON and labelled/unlabelled CSV files are shipped with the UI |
| Three environments | Operational, Benchmark and Test data are visibly separated |
| Environment isolation | Benchmark/Test evidence is not misrepresented as real Mabeli Technology production activity |
| Binary detection | Extra Trees benign vs malicious classifier |
| Attack classification | Extra Trees / Random Forest comparison and best macro-F1 promotion |
| Metrics | Accuracy, weighted precision/recall/F1, macro F1, confusion matrix, classification report |
| Model lifecycle | Version, scope, provenance, training date, feature schema, classes, artifact hash, retraining |
| Explainability | Tree feature-importance evidence returned per prediction |
| Risk | 0–100 score plus configurable low/medium/high/critical severity |
| Auth | No default account; secure first-admin setup and JWT login |
| RBAC | Administrator and Security Analyst roles |
| Dashboard | Operational / Test / Benchmark scopes using real MongoDB detections |
| Single analysis | Real CICIDS-compatible JSON analysis with included genuine benign/PortScan fixtures |
| Batch analysis | Explicit Operational/Test/Benchmark mode plus included labelled/unlabelled CSV fixtures |
| Live monitor | Operational-only Socket.IO stream after persisted detections |
| Live integration | Hashed one-time API keys + authenticated `/api/ingest` |
| Integration check | Safe `/api/ingest/ping` endpoint verifies API-key connectivity without creating detections |
| Collector | CICFlowMeter-compatible CSV flow forwarder |
| Detections | Search/filter history, detail evidence, copy actions and admin deletion |
| Alerts | Operational/Test work queues, status/assignee/notes, copy actions, escalation and admin deletion |
| False positives | Explicit false-positive alert disposition |
| Incidents | Operational/Test cases, status/severity/timeline, linked alerts, copy actions and admin deletion |
| Analytics | Operational / Test / Benchmark / Combined scopes |
| Reports | Scoped PDF management summary and CSV evidence export, including Test scope |
| Audit | Immutable user/admin action history with copyable entity/IP information |
| User management | Add/edit users, roles and active state; copy email; guarded admin deletion |
| Traffic-source management | Create, copy ID/API key, enable/disable, ping-test instructions and admin deletion |
| Settings | Organization, malicious threshold, risk thresholds, grouping window |
| Clipboard UX | Copy controls for IDs, evidence JSON, features, API paths, source URL, API keys, model metadata and schemas |
| Destructive UX | Confirmation dialogs for supported deletes/clears; Audit Log deliberately remains immutable |
| Security | bcrypt, JWT, Helmet, CORS, rate limits, input validation, hashed API keys |
| Reliability | Packaged model fallback, failed ML processing recorded, service/readiness state exposed |
| Responsive UI | Desktop/tablet/mobile custom SOC layout with compact squared visual language |
| Fake operational content | None; included test/benchmark evidence is provenance-labelled and isolated |
| Deployment | Docker Compose plus Windows/Linux/local development instructions |
