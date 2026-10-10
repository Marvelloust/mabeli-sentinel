# Project Scope — Mabeli Sentinel

## Project title

**Design and Implementation of an Intelligent Web and Network Attack Detection and Monitoring System Using Node.js, Python Machine Learning and MongoDB**

## Organization

**Mabeli Technology**

## Core purpose

Mabeli Sentinel provides an intelligent security-monitoring workflow for Mabeli Technology. It
accepts CICIDS-compatible network-flow telemetry, sends feature vectors through a trained
machine-learning service, determines whether the flow is benign or malicious, attempts to classify
the attack family, assigns confidence and risk, stores evidence in MongoDB, correlates repeated
malicious detections into alerts and supports incident investigation from a responsive web interface.

## Technology responsibilities

- Node.js / Express: primary backend, access control, business rules, APIs, reporting and integrations.
- MongoDB: persistent security and operational data.
- Python / scikit-learn: training, evaluation, model persistence and inference.
- CIC-IDS2017: training/evaluation source dataset.
- Socket.IO: live interface updates after committed database writes.

## End-to-end workflow

1. An analyst uploads a real CICIDS-compatible flow file, supplies one compatible flow record, or a
   registered collector sends a live extracted flow.
2. Node.js validates and persists the incoming traffic event.
3. Node.js calls the internal Python ML service.
4. The binary model estimates benign vs malicious probability.
5. When malicious, the multiclass model estimates an attack family.
6. Feature importance is returned as an explanation.
7. Node.js converts attack type + confidence into a 0–100 risk score and severity.
8. The detection is persisted in MongoDB.
9. Malicious events over the configured threshold create or update a correlated alert.
10. Socket.IO updates the analyst UI without refresh.
11. Analysts investigate alerts, record notes, mark false positives or resolve them.
12. Significant alerts can be escalated into incidents with a lifecycle and timeline.
13. Stored information feeds analytics and downloadable reports.
14. Administrators can retrain and replace the model only after evaluation metrics are produced.

## Non-goals and scientific constraints

- The system does not launch attacks.
- The system does not claim that Mabeli Technology has previously been compromised.
- The system does not treat basic HTTP request metadata as a complete CICIDS2017 feature vector.
- The system does not use OpenAI or a chatbot as its detection model.
- No fabricated detections or fake dashboard values are shipped.

## Ready-to-run operating modes

### Benchmark mode

The application ships with a persisted CICIDS2017-derived continuity model and a provenance-labelled genuine benchmark subset. On first use it can immediately exercise the full Node.js → ML → MongoDB detection path and compare predictions against ground truth. Benchmark data is stored with `environment=benchmark` and cannot generate Mabeli Technology alerts or incidents.

### Operational mode

Operational detections represent analyst-submitted or authenticated live-source traffic intended for Mabeli Technology monitoring. Only this environment participates in alert correlation and incident response.

### Research retraining mode

Administrators can train challenger models from larger/full CICIDS2017 data, compare evaluation metrics and promote a new production artifact. Manual retraining is no longer required to make the installed application operational.
