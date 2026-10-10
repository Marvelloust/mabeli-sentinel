# Mabeli Sentinel v2.1 — Interaction + Test Kit Update


> **v4 architecture update:** Mabeli Sentinel is now a multi-organization platform provided by **Mabeli Technology**. A public visitor can create a private organization workspace; they do not become a global platform administrator. Each workspace has isolated security data, team roles, traffic sources, settings and audit history. See `UPGRADE_V4.md` and `docs/MULTI_ORGANIZATION_GUIDE.md`.

**Ready-to-run Machine Learning-Based Web & Network Attack Detection Platform by Mabeli Technology**

Mabeli Sentinel is a Node.js-led security operations system combining an Express API, MongoDB, a Python/scikit-learn detection engine, Socket.IO real-time updates, benchmark validation, alert correlation, incident handling, reporting, model lifecycle controls and authenticated live-flow ingestion.

## What changed in v2/v2.1

This build fixes the first-release problem where the application could start successfully but still required the user to obtain data and train a first model before the core security workflow could be exercised.

The updated build now ships with:

- a **genuinely trained CICIDS2017-derived baseline model artifact** that loads immediately;
- a **genuine CICIDS2017-derived benchmark subset** for offline continuity and end-to-end validation;
- automatic background upgrade to a stronger **20,000-row public CICIDS2017-derived sample** when the ML container has internet access;
- **System Readiness** that verifies Node.js, MongoDB, the ML service, the active model, benchmark data and live-source status;
- a separate **Benchmark Lab** that runs genuine labelled records through the complete Node.js → ML → MongoDB pipeline;
- strict separation between **Benchmark** traffic and **Mabeli Operational** traffic;
- no benchmark record can create a Mabeli operational alert or incident;
- the command overview automatically falls back to a clearly labelled Benchmark view when no live Mabeli traffic exists, rather than presenting an unexplained wall of zeros;
- model provenance, version, artifact hash, training scope and evaluation metrics are visible in the UI.

There are still **no invented Mabeli attacks, fake alerts, hard-coded dashboard totals or fabricated AI decisions**.

## Start the complete application

You only need Docker Desktop for the simplest route.

```bash
docker compose up --build
```

Then open:

```text
http://localhost:4000
```

Create an organization workspace or sign in to an existing one. The detection engine is already operational; you do **not** need to download CICIDS2017 or manually train a model before testing the system.

After sign-in:

1. **System Readiness** shows the real state of every component.
2. **Benchmark Lab** contains genuine CICIDS2017-derived validation traffic.
3. The first benchmark validation is created automatically if the database does not yet contain benchmark detections.
4. **Command Overview** clearly separates Benchmark and Operational views.
5. **Live Operations** remains truthful: it shows only Mabeli-connected/analyst operational traffic.

## The three traffic environments

### Operational

This is actual traffic analyzed for Mabeli Technology. It can come from:

- authenticated live integrations;
- analyst single-flow analysis;
- unlabelled operational CSV batches.

Only Operational malicious detections can create alerts and incidents.

### Benchmark

This is labelled CICIDS2017-derived traffic used to prove and evaluate the ML pipeline. It includes ground truth and accuracy calculations. Benchmark detections are **never represented as attacks against Mabeli Technology** and never create operational alerts.

### Test

This is an isolated setup-verification environment. It uses genuine CICIDS2017-derived fixture records but is deliberately separated from both Benchmark validation and real Mabeli Operational traffic. Test detections can create **Test alerts and Test incidents** so a new installer can verify the complete analyst workflow without fabricating a real Mabeli attack. Test data can be cleared from **Test Centre** without affecting Operational or Benchmark records.

## Ready-to-run ML model

The ZIP includes a persisted scikit-learn model bundle trained from a verified public CICIDS2017-derived preview subset. The subset is deliberately small so the project remains functional without internet access; its metadata labels it as an **offline continuity baseline**, not a full research-grade result.

At ML-service startup, Mabeli Sentinel automatically attempts to obtain the public 20,000-row CICIDS2017-derived sample and, if successful, trains and promotes the stronger baseline. The offline model remains active if that upgrade is unavailable.

For a final academic report, you should still retrain on the complete official CICIDS2017 data and report those final metrics. This is now an **optional research/evaluation step**, not a prerequisite for making the application work.

## Technology ownership

- **Node.js + Express** — main application/backend authority and API.
- **MongoDB** — users, traffic, detections, benchmark runs, alerts, incidents, settings, integrations, model records and audit logs.
- **Python + FastAPI + scikit-learn** — model bootstrap, training, evaluation and inference.
- **HTML/CSS/JavaScript + Socket.IO** — custom responsive Mabeli Sentinel interface and live updates.

## Included modules

- Public sign-in + private organization registration — no random visitor becomes a platform administrator
- Multi-organization workspace isolation
- Owner / Administrator / Security Analyst / Viewer organization roles
- Team add/edit/revoke/restore/remove controls
- Guided onboarding and in-product Help
- JWT authentication
- Administrator / Security Analyst roles
- System Readiness
- Production model bootstrap and provenance
- Automatic stronger-baseline upgrade
- Benchmark Lab
- Binary benign/malicious detection
- Multiclass attack classification
- Confidence and malicious-probability scoring
- Risk scoring and severity classification
- Explainable feature importance
- Command Overview with Operational / Benchmark scopes
- Operational Live Monitor
- Single-flow analysis
- Label-aware CSV batch analysis
- Detection history with environment filtering
- Ground-truth comparison for benchmark detections
- Correlated operational alerts
- Alert investigation notes and statuses
- Alert-to-incident escalation
- Incident lifecycle and timeline
- Operational / Benchmark analytics scopes
- PDF management reporting
- CSV evidence export
- Model versioning and artifact SHA-256
- Extra Trees / Random Forest comparison for retraining
- Authenticated collector integration keys
- CICFlowMeter-compatible flow forwarder
- User management
- Audit log
- Detection threshold and risk settings
- Responsive desktop/tablet/mobile UI
- Docker Compose deployment

## Test Centre and included fixtures

A new **Test Centre** is included for complete first-run verification. It can:

- run genuine benign, PortScan, DDoS, DoS Hulk and Web Attack Brute Force fixtures through the real ML model;
- generate isolated Test detections;
- create Test alerts from genuine malicious predictions;
- create a linked Test incident so the investigation workflow can be verified;
- clear all Test data without touching Operational or Benchmark data;
- provide downloadable Single Analysis and Batch Analysis fixtures.

Included browser-downloadable files:

```text
frontend/public/test-data/single-benign.json
frontend/public/test-data/single-portscan.json
frontend/public/test-data/batch-labelled.csv
frontend/public/test-data/batch-unlabelled.csv
```

Recommended setup verification:

1. Start the stack and create the first administrator.
2. Open **System Readiness**.
3. Open **Test Centre** and click **Generate complete test workspace**.
4. Open **Detections → Test**, **Alerts → Test**, and **Incidents → Test**.
5. Verify View, Copy, Edit/Update and Delete actions.
6. Use the included JSON/CSV fixtures in Single Analysis and Batch Analysis.
7. Create a Traffic Source and use the generated `/api/ingest/ping` command to verify the API key without creating a detection.
8. Only then connect real Mabeli traffic and work in Operational views.

See `docs/TEST_KIT.md` for the full walkthrough and expected outcomes.

## CRUD and copy actions

The UI now exposes the expected small operational controls instead of hiding them:

- detections: View, Copy ID/evidence/features, Delete (admin);
- alerts: View, Copy alert/detection IDs, update status/notes, escalate, Delete (admin);
- incidents: View, Copy IDs, timeline updates, Delete (admin);
- traffic sources: Copy integration ID/API key/test commands, enable/disable, Delete;
- users: Copy email, Edit, enable/disable, Delete with safety protections;
- model: Copy model version, artifact SHA-256 and feature schema;
- reports: Copy generated API paths;
- audit log: Copy entity IDs/IPs, but **no delete** because the audit trail is treated as security evidence.

Destructive actions require confirmation. Your own user account and the last active administrator cannot be deleted.

## Scientific live-monitoring boundary

CICIDS2017 is based on network-flow features. A normal Express request does not contain the full feature vector required by a CICIDS-trained model. Live monitoring therefore uses an authorized flow collector or compatible feature extractor and sends compatible flow features to Mabeli Sentinel.

The path is:

```text
Network / web-server traffic
        ↓
Flow collector / feature extractor
        ↓
Authenticated Node.js ingestion API
        ↓
Python ML model
        ↓
Prediction + confidence + explanation
        ↓
MongoDB
        ↓
Operational alert / incident workflow
```

## Benchmark validation workflow

```text
Genuine labelled CICIDS2017-derived record
        ↓
Node.js benchmark controller
        ↓
Python production model
        ↓
Prediction
        ↓
MongoDB traffic event + detection
        ↓
Prediction compared with ground truth
        ↓
Benchmark accuracy + attack distribution
```

No operational alert is created in this flow.

## Optional full CICIDS2017 retraining

If you want final research metrics from the full official dataset, place the CSVs under:

```text
ml-service/data/cicids2017/
```

Inside Docker that appears to the ML service as:

```text
/data/cicids2017
```

Then open **Model Intelligence → Research retraining** and train the challenger model. The application remains fully usable before doing this.

The helper scripts remain available if desired:

```bash
python scripts/download_cicids2017.py
```

or a smaller external sample:

```bash
python scripts/download_cicids2017.py --sample
```

These commands are no longer part of the required startup process.

## Live integration

As an administrator:

1. Open **Integrations**.
2. Create a CICFlowMeter / Flow Forwarder integration.
3. Copy the generated key once.
4. Forward authorized flow CSV output:

```bash
python collector/flow_forwarder.py "C:\path\to\cicflowmeter-output.csv" --api-key "ms_your_key_here"
```

## Manual local development without Docker

Start MongoDB locally, then:

### ML service

```bash
cd ml-service
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

### Node.js app

```bash
cd backend
npm install
# copy .env.example .env on Windows, or cp .env.example .env on Linux/macOS
npm start
```

Open `http://localhost:4000`.

## Updating from the earlier ZIP

If your existing installation only contains your administrator account and no important traffic history, the cleanest update is:

```bash
docker compose down
```

Replace the old project files with this v2 folder, then:

```bash
docker compose up --build
```

You may keep the existing MongoDB volume; the new application will create its new benchmark collections/fields as required. If you deliberately want a completely clean database, `docker compose down -v` removes the volume, **but it also deletes existing users and stored security data**.

## Production hardening

Before public deployment:

- replace `JWT_SECRET`;
- use HTTPS / reverse proxy;
- keep MongoDB and the ML service private;
- set the correct frontend origin;
- back up MongoDB and `ml-service/models`;
- only collect traffic on infrastructure you are authorized to monitor;
- report model metrics together with their exact dataset/training scope.

## Academic framing

**Recommended title**

Design and Implementation of an Intelligent Web and Network Attack Detection and Monitoring System Using Node.js, Python Machine Learning and MongoDB

**Organization**

Mabeli Technology

**Short explanation**

Mabeli Sentinel is a Node.js-based cybersecurity platform that uses a CICIDS2017-trained machine-learning service to classify compatible network-flow traffic, store detections in MongoDB, calculate security risk, validate the model against labelled benchmark traffic, and generate real-time operational alerts and incidents for connected Mabeli Technology systems.

See `docs/`, `VALIDATION.md`, and `ml-service/data/benchmark/PROVENANCE.json` for implementation and provenance details.
