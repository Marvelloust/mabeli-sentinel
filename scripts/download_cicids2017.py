"""Download the official CIC-IDS2017 MachineLearningCSV archive.

The dataset is deliberately not bundled into this project: the official archive is large,
and its provenance should remain explicit. This helper downloads from the University of
New Brunswick CIC dataset host and extracts into ml-service/data/cicids2017.
"""
from __future__ import annotations
import argparse
import shutil
import urllib.request
import zipfile
from pathlib import Path

OFFICIAL = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/MachineLearningCSV.zip"
SAMPLE = "https://raw.githubusercontent.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/main/data/CICIDS2017_sample.csv"


def download(url: str, target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mabeli-Sentinel/1.0"})
    with urllib.request.urlopen(req, timeout=120) as response, target.open("wb") as out:
        total = int(response.headers.get("Content-Length") or 0)
        copied = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            copied += len(chunk)
            if total:
                print(f"\rDownloaded {copied / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MB", end="")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", action="store_true", help="Download a public sampled CICIDS2017 CSV instead of the full archive")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    dest = root / "ml-service" / "data" / "cicids2017"
    dest.mkdir(parents=True, exist_ok=True)

    if args.sample:
        target = dest / "CICIDS2017_sample.csv"
        print("Downloading the public sampled CICIDS2017 CSV...")
        download(SAMPLE, target)
        print(f"Saved to {target}")
        return

    archive = root / "ml-service" / "data" / "MachineLearningCSV.zip"
    print("Downloading official CIC-IDS2017 MachineLearningCSV archive from UNB CIC...")
    download(OFFICIAL, archive)
    print("Extracting...")
    with zipfile.ZipFile(archive) as z:
        z.extractall(dest)
    # Flatten common nested MachineLearningCVE folder if present without deleting source.
    nested = next((p for p in dest.rglob("*.csv") if p.parent != dest), None)
    if nested:
        for csv_path in dest.rglob("*.csv"):
            if csv_path.parent != dest:
                shutil.copy2(csv_path, dest / csv_path.name)
    print(f"CICIDS2017 CSVs are ready in {dest}")


if __name__ == "__main__":
    main()
