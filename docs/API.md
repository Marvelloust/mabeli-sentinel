# API Overview — v2 + Test/CRUD update

All `/api/*` endpoints except setup, login and authenticated integration ingestion require a Bearer JWT.

## Setup and authentication
- `GET /api/setup/status`
- `POST /api/setup/admin`
- `POST /api/auth/login`
- `GET /api/auth/me`

## System state
- `GET /api/system/health` — service status.
- `GET /api/system/readiness` — services, production model, benchmark source, detection counts and integration heartbeats.
- `POST /api/system/validate` — real 12-record end-to-end benchmark validation.

## Command / benchmark
- `GET /api/dashboard?scope=operational|test|benchmark|all`
- `POST /api/benchmark/ensure` — idempotent first-run benchmark population.
- `GET /api/benchmark` — benchmark source, aggregate results and run history.
- `POST /api/benchmark/run` — run 10–1000 genuine benchmark records.
- `DELETE /api/benchmark/data` — admin-only benchmark reset.

## Analysis and detections
- `POST /api/analysis/single` — single-flow analysis; `meta.environment=test` keeps setup verification isolated, otherwise Operational.
- `POST /api/analysis/batch` — supports explicit `test|benchmark|operational`; otherwise labelled CSV defaults to Benchmark and unlabelled CSV defaults to Operational.
- `GET /api/detections?environment=operational|test|benchmark`
- `GET /api/detections/:id`
- `DELETE /api/detections/:id` — admin; cascades the captured traffic event and directly linked alert(s).

## Response workflow
- `GET/PATCH /api/alerts` — Operational by default; `?environment=test` for isolated test alerts.
- `DELETE /api/alerts/:id` — admin.
- `GET/POST/PATCH /api/incidents` — supports Operational and Test incidents.
- `DELETE /api/incidents/:id` — admin.
- `GET /api/analytics?scope=operational|test|benchmark|all`
- `GET /api/reports/security.pdf?scope=...`
- `GET /api/reports/security.csv?scope=...`

## Test Centre
- `GET /api/test-kit` — fixture availability and Test-environment counts.
- `POST /api/test-kit/scenario` — run one genuine CICIDS2017-derived setup-verification scenario.
- `POST /api/test-kit/full` — generate a complete isolated Test workspace with detections and, when the model produces a malicious decision, a Test alert and linked Test incident.
- `DELETE /api/test-kit/data` — admin; clears only Test-environment records.

## Model lifecycle
- `GET /api/model`
- `GET /api/model/bootstrap`
- `POST /api/model/upgrade` — retry public baseline upgrade.
- `POST /api/model/train` — administrator research retraining.

## Administration
- `GET/PATCH /api/settings`
- `GET/POST/PATCH /api/users`
- `DELETE /api/users/:id` — admin; protects the current user and last active administrator.
- `GET /api/audit`
- `GET/POST/PATCH /api/integrations`
- `DELETE /api/integrations/:id` — admin.
- `POST /api/ingest/ping` — API-key connectivity/heartbeat check without creating a detection.
- `POST /api/ingest` — authenticated operational flow ingestion using `x-api-key`.
