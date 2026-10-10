# Mabeli Sentinel Architecture — v2

## Operational runtime path

`Authorized flow source → Node.js ingestion → Python ML service → risk engine → MongoDB → alert/incident logic → Socket.IO → analyst UI`

Node.js remains the application authority. It owns authentication, authorization, environment isolation, storage, risk scoring, alert correlation, incidents, reporting, integrations and audit logging. Python owns model bootstrap, data preparation, training, evaluation and inference.

## Benchmark runtime path

`CICIDS2017-derived labelled record → Node.js benchmark controller → same production ML model → MongoDB benchmark detection → ground-truth comparison → BenchmarkRun metrics`

The benchmark path deliberately calls the same production inference service and persists through the same database layer, but `environment=benchmark` prevents it from creating operational alerts or incidents.

## Ready-to-run model lifecycle

1. ML service loads the packaged persisted model artifact.
2. If absent, it can retrain from the bundled verified CICIDS2017-derived fallback subset.
3. Startup can asynchronously attempt to retrieve the public 20,000-row sample.
4. If retrieval/training succeeds, the stronger model is atomically promoted.
5. If remote upgrade fails, the existing model remains active.
6. Administrators can later retrain against the full official CICIDS2017 dataset.

## ML boundary

CICIDS2017 contains flow-level features. A raw browser HTTP request does **not** contain the complete feature vector required by the trained model. Live mode therefore expects a compatible flow collector such as CICFlowMeter, or another feature extractor that produces equivalent numerical flow fields.

## Real-time behavior

Every successful prediction is persisted before broadcast. Socket.IO is a presentation/update channel; MongoDB remains the source of truth. Operational live feeds explicitly filter benchmark events.

## Alert correlation

Only malicious **operational** detections can create alerts. Related events are grouped by attack type, source IP and destination IP during the configured time window so repeated events update a single alert rather than flooding analysts.

## Realtime authentication

Socket.IO connections are authenticated with the same signed JWT used by the HTTP application. Unauthenticated or expired sessions cannot subscribe to the realtime detection stream.
