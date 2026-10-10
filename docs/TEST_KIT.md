# Mabeli Sentinel Test Kit

This document is for anyone setting up Mabeli Sentinel for the first time and wondering what to click, what data to use, and what a successful result should look like.

The Test Kit exists so the complete product can be exercised without pretending that benchmark attacks happened to Mabeli Technology.

## The three environments

### Operational
Real Mabeli-connected or intentionally operational analyst traffic. Malicious predictions can create real Operational alerts and incidents.

### Benchmark
Labelled CICIDS2017-derived validation traffic. Used to measure model behaviour and compare predictions with ground truth. It never creates Operational alerts.

### Test
Isolated setup-verification traffic. It uses genuine CICIDS2017-derived fixtures, but records are marked Test. Test detections can create Test alerts and Test incidents so the full workflow can be checked safely.

## Fastest complete setup test

1. Start the stack.
2. Create the first administrator.
3. Open **System Readiness** and confirm API, MongoDB, ML service, Production Model and Benchmark Traffic are ready.
4. Open **Test Centre**.
5. Click **Generate complete test workspace**.
6. Open **Test Dashboard**, **Test Detections**, **Test Alerts**, and **Test Incidents**.
7. Verify copy, update and delete actions.
8. Open **Traffic Sources**, create one integration and use the generated `/api/ingest/ping` command.

A successful complete test should produce Test detections. If the active model flags one of the malicious fixtures as malicious, it also produces a Test alert and a linked Test incident. The exact attack prediction depends on the active trained model; Sentinel does not hard-code a successful prediction.

## Included real test files

These files are served by the running application and also live in `frontend/public/test-data/`.

### `single-benign.json`
Use on **Single Analysis**. It is a genuine CICIDS2017-derived benign flow fixture.

### `single-portscan.json`
Use on **Single Analysis**. It is a genuine CICIDS2017-derived PortScan-labelled flow fixture.

### `batch-labelled.csv`
Use on **Batch Analysis**. It contains mixed genuine CICIDS2017-derived labelled records. Choose **Benchmark** or **Auto** if you want ground-truth evaluation.

### `batch-unlabelled.csv`
Use on **Batch Analysis**. It contains the same style of flow records without labels. Choose **Test** to exercise isolated detection/alert behaviour without polluting Operational data.

## Single Analysis test

Open **Single Analysis**.

1. Leave Environment on **Test**.
2. Click **Load benign fixture**.
3. Click **Run model analysis**.
4. Copy the generated detection ID.
5. Repeat with **Load PortScan fixture**.

Expected behaviour:

- a real model prediction is returned;
- confidence and risk are calculated;
- the detection is stored in MongoDB under `environment=test`;
- a malicious prediction above the current threshold may create a Test alert;
- the record appears under **Detections → Test**.

## Batch Analysis test

Open **Batch Analysis**.

### Benchmark test

1. Download `batch-labelled.csv` from the page.
2. Select the file.
3. Choose **Benchmark** or **Auto**.
4. Run the analysis.

Expected behaviour:

- every row is sent through the ML model;
- ground truth is stored;
- class-match information is available;
- no Operational alert is created.

### Isolated alert-path test

1. Download `batch-unlabelled.csv`.
2. Choose **Test**.
3. Run the analysis.

Expected behaviour:

- rows are stored under Test;
- malicious predictions may create Test alerts;
- Operational dashboards remain unaffected.

## Detection page test

Open **Detections** and select **Test**.

Verify:

- View opens evidence details;
- Copy ID works;
- Copy evidence JSON works;
- Copy features works;
- filters work;
- an administrator can Delete a detection;
- deletion asks for confirmation;
- deleting a detection also deletes its captured traffic event and directly linked alert.

## Alert page test

Open **Alerts → Test**.

If there is no Test alert yet, return to **Test Centre** and run **Generate complete test workspace**.

Verify:

- alert detail drawer opens;
- status can be changed;
- investigation notes can be saved;
- alert ID and detection ID can be copied;
- the alert can be escalated to a Test incident;
- an administrator can delete the alert;
- deleting the alert does not delete the underlying detection.

## Incident page test

Open **Incidents → Test**.

Verify:

- linked alert count is visible;
- incident ID and linked alert IDs can be copied;
- status can move through Open → Investigating → Contained → Resolved;
- timeline notes are stored;
- an administrator can delete the incident;
- deleting an incident does not delete its linked alerts or detections.

## Analytics test

Open **Analytics → Test** after generating Test data.

Expected behaviour:

- confidence summary uses stored Test detections;
- attack distribution uses Test malicious predictions;
- severity distribution uses Test risk calculations;
- Test analytics are clearly labelled and separate from Operational analytics.

## Report test

Open **Reports**.

Choose **Isolated Test environment** and download:

- PDF report;
- CSV evidence export.

You can also copy each generated API path.

## Traffic Source test without creating a detection

Open **Traffic Sources** as an administrator.

1. Create an integration.
2. Copy the API key immediately.
3. Copy the generated cURL or PowerShell ping command.
4. Run it from your terminal.

The command calls:

```text
POST /api/ingest/ping
```

with the generated `x-api-key`.

Expected behaviour:

- the endpoint returns success;
- the integration's **Last seen** timestamp updates;
- no traffic detection is created.

This lets you verify API-key authentication safely before sending live flow data.

## User-management test

As an administrator:

1. Add a Security Analyst user.
2. Copy the email from the table.
3. Edit the name or role.
4. Disable and re-enable the account.
5. Delete the test account.

Safety rules:

- you cannot delete your own currently logged-in account;
- the last active administrator cannot be deleted;
- audit records remain even if a user account is removed.

## Model page test

Open **Model Intelligence**.

Verify Copy actions for:

- model version;
- model artifact SHA-256;
- feature schema.

Download a Single Analysis fixture directly from this page if needed.

## Audit log behaviour

The Audit Log intentionally has no delete button. This is not a missing feature: audit records are treated as security evidence.

You can copy entity IDs and IP addresses for reviews.

## Clearing test data

Open **Test Centre** and click **Clear all test data**.

Only `environment=test` records are removed:

- Test traffic events;
- Test detections;
- Test alerts;
- Test incidents.

Operational and Benchmark records are not affected.

## Important note about expected predictions

The included fixtures have known CICIDS2017 ground-truth labels, but the application deliberately does not fake or hard-code the machine-learning answer. The active model can make a correct or incorrect prediction. That is exactly what a real machine-learning system should show.

For final academic evaluation, retrain using the full official CICIDS2017 dataset and report the resulting metrics honestly.
