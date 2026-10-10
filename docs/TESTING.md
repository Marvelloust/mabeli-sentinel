# Validation Checklist — v2

## First-run readiness

1. Start `docker compose up --build`.
2. Confirm the ML healthcheck succeeds only when a model artifact is loaded.
3. Create the first administrator.
4. Confirm **System Readiness** reports Node API, MongoDB, ML service, model and benchmark availability.
5. Confirm a first benchmark run can be created without downloading or training anything manually.
6. Confirm Command Overview automatically shows a clearly-labelled Benchmark scope while operational traffic is zero.

## Benchmark isolation

1. Run **Benchmark Lab** validation.
2. Confirm TrafficEvent + Detection documents use `environment=benchmark`.
3. Confirm ground truth and exact-class correctness are stored.
4. Confirm binary accuracy and exact-class accuracy are calculated for BenchmarkRun.
5. Confirm benchmark malicious predictions create **no Alert documents** and no Mabeli incidents.
6. Confirm benchmark records do not appear in **Live Operations**.

## Operational workflow

1. Submit a compatible single flow and confirm `environment=operational`.
2. Process an unlabelled CSV and confirm operational persistence.
3. Confirm malicious operational predictions above threshold generate correlated alerts.
4. Update alert status and confirm audit entry appears.
5. Escalate an alert to an incident and update the incident timeline.
6. Create an integration and verify the plaintext API key is shown once.
7. Forward compatible live-flow CSV records and observe Socket.IO updates without refresh.
8. Export Operational PDF and CSV reports.

## Model lifecycle

1. Confirm packaged model metadata exposes scope, source, version and SHA-256.
2. If internet is available, confirm the background public-baseline upgrade moves bootstrap state through `upgrading` to `ready`.
3. Confirm the existing model remains usable if remote upgrade fails.
4. Retrain with full CICIDS2017 and confirm the new model version is persisted and promoted.

## Security

- Invalid/missing JWT returns 401.
- Analyst cannot access admin-only user/integration/settings/audit endpoints.
- Invalid integration API key returns 401.
- First-admin setup returns 409 after initialization.
- Passwords are stored only as bcrypt hashes.
- Benchmark ingestion never produces operational alerts.
- Secrets are changed before public deployment.
