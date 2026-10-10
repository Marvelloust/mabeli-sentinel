"""Forward CICFlowMeter/CICIDS-compatible CSV flow rows to Mabeli Sentinel.

This is a defensive ingestion adapter. It does not generate attack traffic. Point it at
CSV output produced by an authorized flow collector, then it sends numeric flow features
through the authenticated /api/ingest endpoint.
"""
from __future__ import annotations
import argparse
import csv
import json
import time
import urllib.request
from pathlib import Path

NON_FEATURES = {"Label", "Flow ID", "Source IP", "Destination IP", "Timestamp", "Src IP", "Dst IP"}


def numeric_features(row):
    features = {}
    for key, value in row.items():
        key = str(key).strip()
        if key in NON_FEATURES:
            continue
        try:
            num = float(str(value).strip())
            if num == num and num not in (float("inf"), float("-inf")):
                features[key] = num
        except Exception:
            pass
    return features


def post(url, api_key, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url.rstrip("/") + "/api/ingest", data=data, method="POST", headers={
        "Content-Type": "application/json", "x-api-key": api_key, "User-Agent": "Mabeli-Sentinel-Flow-Forwarder/1.0"
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("csv", type=Path)
    p.add_argument("--server", default="http://localhost:4000")
    p.add_argument("--api-key", required=True)
    p.add_argument("--delay", type=float, default=0.0, help="Seconds between records; 0 sends as fast as predictions complete")
    args = p.parse_args()
    with args.csv.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        for number, row in enumerate(csv.DictReader(fh), 1):
            features = numeric_features(row)
            if not features:
                continue
            meta = {
                "sourceIp": row.get("Source IP") or row.get("Src IP"),
                "destinationIp": row.get("Destination IP") or row.get("Dst IP"),
                "sourcePort": row.get("Source Port") or row.get("Src Port"),
                "destinationPort": row.get("Destination Port") or row.get("Dst Port"),
                "protocol": row.get("Protocol"),
                "rawLabel": row.get("Label")
            }
            try:
                result = post(args.server, args.api_key, {"features": features, "meta": meta})
                det = result.get("detection", {})
                print(f"{number}: {det.get('prediction')} | {det.get('attackType')} | confidence={det.get('confidence')}")
            except Exception as exc:
                print(f"{number}: forwarding failed: {exc}")
            if args.delay:
                time.sleep(args.delay)


if __name__ == "__main__":
    main()
