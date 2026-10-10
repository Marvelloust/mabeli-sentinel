# Mabeli Sentinel v2.1 — Validation Performed Before Patch Packaging

Validation date: **2026-09-15**

## Passed checks

- Node.js syntax validation passed for all modified backend JavaScript source files.
- Frontend JavaScript syntax validation passed after the Test Centre, copy/delete controls, filtering and fixture-workflow update.
- Existing Python ML service remains unchanged by this patch; the packaged persisted model and benchmark subsystem remain intact.
- Test-environment schema support is present in TrafficEvent, Detection, Alert and Incident records.
- Test data is isolated from Operational and Benchmark scopes in dashboard, detections, alerts, incidents, analytics and reports.
- Test Centre scenario endpoints use genuine bundled CICIDS2017-derived benchmark records and the actual ML prediction service; predictions are not hard-coded.
- Full Test Centre workflow can create detections, a threshold-qualified test alert and a linked test incident without polluting Mabeli operational records.
- Included browser fixtures exist and are provenance-labelled:
  - `frontend/public/test-data/single-benign.json`
  - `frontend/public/test-data/single-portscan.json`
  - `frontend/public/test-data/batch-labelled.csv`
  - `frontend/public/test-data/batch-unlabelled.csv`
- Detection, alert, incident, user and traffic-source deletion endpoints are administrator-only.
- User deletion protects the current administrator and the final active administrator account.
- Alert deletion unlinks the alert from incidents; detection deletion also removes its directly-linked alert(s) and underlying traffic event.
- Audit Log has no delete endpoint by design because it is security evidence.
- Clipboard controls are available for security identifiers, evidence/features, source information, report API paths, model metadata and integration credentials where useful.
- Traffic-source connectivity can be tested with `/api/ingest/ping` without creating a security detection.
- Benchmark history and isolated Test Centre data each have explicit administrator clear actions with confirmation.
- UI destructive actions require confirmation rather than deleting immediately.
- Existing packaged production model, genuine benchmark fallback and first-run benchmark behavior are preserved.

## Packaging-runtime limitation

The packaging environment does not provide a MongoDB daemon/Docker runtime, so this patch was validated statically at the Node/frontend level and against the existing project structure rather than by launching the complete Compose stack here. Apply the patch to Mabeli Sentinel Complete v2/v3 and rebuild the app container so the modified frontend and backend are loaded.

## Recommended post-patch verification

1. Open **Test Centre** and click **Generate complete test workspace**.
2. Open **Command Overview → Test** and confirm the new detections are visible.
3. Open **Detections → Test**, copy an ID, inspect evidence, then test deletion with an administrator account if desired.
4. Open **Alerts → Test** and **Incidents → Test** to exercise investigation, escalation and delete flows.
5. Use the included benign and PortScan JSON fixtures in **Single Analysis**.
6. Use the included labelled/unlabelled CSV fixtures in **Batch Analysis**.
7. Create a Traffic Source and use the generated safe ping command to verify its API key and heartbeat.
