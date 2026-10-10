from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

BASE = Path(__file__).resolve().parents[1]
MODEL_DIR = BASE / 'models'
REPORT_DIR = BASE / 'reports'
DATA_DIR = Path(os.getenv('SENTINEL_DATA_DIR', str(BASE / 'data'))).expanduser().resolve()
BENCHMARK_DIR = DATA_DIR / 'benchmark'
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

BUNDLE_PATH = MODEL_DIR / 'sentinel_bundle.joblib'
META_PATH = MODEL_DIR / 'meta.json'
FALLBACK_DATASET = BENCHMARK_DIR / 'cicids2017_verified_preview.csv'
PROVENANCE_PATH = BENCHMARK_DIR / 'PROVENANCE.json'
PUBLIC_SAMPLE_PATH = BENCHMARK_DIR / 'cicids_sample.parquet'
PUBLIC_SAMPLE_URL = os.getenv(
    'CICIDS_PUBLIC_SAMPLE_URL',
    'https://huggingface.co/datasets/transformer112/cicids2017-ids-dataset/resolve/main/cicids_sample.parquet?download=true',
)
AUTO_BOOTSTRAP_REMOTE = os.getenv('AUTO_BOOTSTRAP_REMOTE', 'true').lower() not in {'0', 'false', 'no'}

app = FastAPI(title='Mabeli Sentinel ML Service', version='2.0.0')
_bundle: dict[str, Any] | None = None
_meta: dict[str, Any] | None = None
_train_lock = threading.Lock()
_benchmark_cache: tuple[str, float, pd.DataFrame] | None = None
_bootstrap_state: dict[str, Any] = {
    'state': 'idle',
    'message': 'Bootstrap has not started',
    'started_at': None,
    'completed_at': None,
    'last_error': None,
    'remote_upgrade_available': True,
}

NUMERIC_SAMPLE_LABELS = {
    '0': 'BENIGN', '1': 'Bot', '2': 'BruteForce', '3': 'DoS',
    '4': 'Infiltration', '5': 'PortScan', '6': 'WebAttack'
}

LABEL_ALIASES = {
    'BENIGN': 'BENIGN',
    'Web Attack � Brute Force': 'Web Attack Brute Force',
    'Web Attack – Brute Force': 'Web Attack Brute Force',
    'Web Attack - Brute Force': 'Web Attack Brute Force',
    'Web Attack � XSS': 'Web Attack XSS',
    'Web Attack – XSS': 'Web Attack XSS',
    'Web Attack - XSS': 'Web Attack XSS',
    'Web Attack � Sql Injection': 'Web Attack Sql Injection',
    'Web Attack – Sql Injection': 'Web Attack Sql Injection',
    'Web Attack - Sql Injection': 'Web Attack Sql Injection',
}

DROP_NAME_PATTERNS = [
    r'^flow id$', r'^source ip$', r'^destination ip$', r'^src ip$', r'^dst ip$',
    r'^timestamp$', r'^label$', r'^label_binary$', r'^attack$', r'^class$'
]


class PredictRequest(BaseModel):
    features: dict[str, Any]


class BatchRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class TrainRequest(BaseModel):
    dataset_path: str
    sample_limit: int | None = Field(default=None, ge=20)
    random_state: int = 42


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_bundle() -> None:
    global _bundle, _meta
    if BUNDLE_PATH.exists() and META_PATH.exists():
        _bundle = joblib.load(BUNDLE_PATH)
        _meta = json.loads(META_PATH.read_text(encoding='utf-8'))


def normalize_label(value: Any) -> str:
    s = str(value).strip()
    s = NUMERIC_SAMPLE_LABELS.get(s, s)
    s = LABEL_ALIASES.get(s, s)
    s = s.replace('�', '-').replace('–', '-').strip()
    s = re.sub(r'\s+', ' ', s)
    if s.upper() == 'BENIGN':
        return 'BENIGN'
    s = s.replace('Web Attack - ', 'Web Attack ')
    return s


def read_one(file: Path) -> pd.DataFrame:
    if file.suffix.lower() in {'.parquet', '.pq'}:
        return pd.read_parquet(file)
    try:
        return pd.read_csv(file, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        return pd.read_csv(file, encoding='cp1252', low_memory=False)


def read_dataset(path_str: str) -> pd.DataFrame:
    path = Path(path_str).expanduser().resolve()
    if not path.exists():
        raise HTTPException(400, f'Dataset path does not exist: {path}')
    if path.is_dir():
        files = sorted([*path.glob('*.csv'), *path.glob('*.parquet'), *path.glob('*.pq')])
    else:
        files = [path]
    if not files:
        raise HTTPException(400, 'No CSV or Parquet files were found')
    frames = [read_one(file) for file in files]
    return pd.concat(frames, ignore_index=True)


def stratified_cap(df: pd.DataFrame, label_col: str, limit: int, seed: int) -> pd.DataFrame:
    if len(df) <= limit:
        return df
    groups = []
    counts = df[label_col].value_counts()
    minimum_per_class = min(100, max(2, limit // max(1, len(counts) * 10)))
    remaining = limit
    for _, group in df.groupby(label_col):
        n = min(len(group), minimum_per_class, max(0, remaining))
        if n:
            groups.append(group.sample(n=n, random_state=seed))
            remaining -= n
    if remaining > 0:
        used_idx = pd.concat(groups).index if groups else []
        rest = df.drop(index=used_idx)
        if len(rest):
            groups.append(rest.sample(n=min(remaining, len(rest)), random_state=seed))
    return pd.concat(groups).sample(frac=1, random_state=seed).reset_index(drop=True)


def prepare(df: pd.DataFrame, sample_limit: int | None, seed: int):
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    label_col = next((c for c in df.columns if c.lower() in {'label', 'attack', 'class'}), None)
    if not label_col:
        raise HTTPException(400, 'Dataset must contain a Label column')
    df[label_col] = df[label_col].map(normalize_label)
    df = df[df[label_col].notna()]
    if sample_limit:
        df = stratified_cap(df, label_col, sample_limit, seed)

    candidate_cols = []
    for col in df.columns:
        if any(re.match(p, col, flags=re.I) for p in DROP_NAME_PATTERNS):
            continue
        numeric = pd.to_numeric(df[col], errors='coerce')
        if numeric.notna().sum() >= max(10, int(len(df) * 0.50)):
            df[col] = numeric
            candidate_cols.append(col)
    if len(candidate_cols) < 5:
        raise HTTPException(400, 'Insufficient numeric CICIDS-compatible features after cleaning')

    X = df[candidate_cols].replace([np.inf, -np.inf], np.nan)
    medians = X.median(numeric_only=True).fillna(0.0)
    X = X.fillna(medians).astype(float)
    y_multi = df[label_col].astype(str)
    y_binary = np.where(y_multi.str.upper().eq('BENIGN'), 'benign', 'malicious')

    useful = [c for c in X.columns if X[c].nunique(dropna=False) > 1]
    X = X[useful]
    medians = medians[useful]
    return X, y_binary, y_multi, medians


def evaluate(y_true, y_pred, labels=None):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted', zero_division=0)
    macro = precision_recall_fscore_support(y_true, y_pred, average='macro', zero_division=0)
    return {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision_weighted': float(p),
        'recall_weighted': float(r),
        'f1_weighted': float(f),
        'f1_macro': float(macro[2]),
        'classification_report': classification_report(y_true, y_pred, output_dict=True, zero_division=0),
        'confusion_matrix': confusion_matrix(y_true, y_pred, labels=labels).tolist() if labels else confusion_matrix(y_true, y_pred).tolist(),
    }


def dataset_metadata(path: Path, records: int) -> dict[str, Any]:
    resolved = path.resolve()
    if resolved == FALLBACK_DATASET.resolve():
        provenance = {}
        if PROVENANCE_PATH.exists():
            provenance = json.loads(PROVENANCE_PATH.read_text(encoding='utf-8'))
        return {
            'training_scope': 'verified-preview-fallback',
            'source_name': 'CICIDS2017 verified public preview subset',
            'source_url': provenance.get('source_repository'),
            'research_grade': False,
            'scope_note': 'Offline continuity model. Automatically superseded when the 20,000-row public sample is available.',
            'records': records,
        }
    if resolved == PUBLIC_SAMPLE_PATH.resolve():
        return {
            'training_scope': 'public-20k-sample',
            'source_name': 'CICIDS2017 20,000-row public sample',
            'source_url': 'https://huggingface.co/datasets/transformer112/cicids2017-ids-dataset',
            'research_grade': True,
            'scope_note': 'Public CICIDS2017-derived 20K sample used as the ready-to-run baseline. Full official CICIDS2017 retraining remains supported.',
            'records': records,
        }
    return {
        'training_scope': 'user-supplied-cicids',
        'source_name': str(resolved),
        'source_url': None,
        'research_grade': True,
        'scope_note': 'User-supplied CICIDS-compatible dataset.',
        'records': records,
    }


def train_pipeline(req: TrainRequest) -> dict[str, Any]:
    global _bundle, _meta
    with _train_lock:
        path = Path(req.dataset_path).expanduser().resolve()
        df = read_dataset(req.dataset_path)
        X, y_bin, y_multi, medians = prepare(df, req.sample_limit, req.random_state)
        if len(set(y_bin)) < 2:
            raise HTTPException(400, 'Dataset must contain both benign and malicious records')
        if len(set(y_multi)) < 2:
            raise HTTPException(400, 'Dataset must contain at least two traffic classes')

        indices = np.arange(len(X))
        stratify = y_multi if y_multi.value_counts().min() >= 2 else y_bin
        train_idx, test_idx = train_test_split(indices, test_size=0.20, random_state=req.random_state, stratify=stratify)
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        bin_train, bin_test = np.asarray(y_bin)[train_idx], np.asarray(y_bin)[test_idx]
        multi_train, multi_test = y_multi.iloc[train_idx], y_multi.iloc[test_idx]

        binary_model = ExtraTreesClassifier(
            n_estimators=220, class_weight='balanced', random_state=req.random_state,
            n_jobs=-1, min_samples_leaf=1 if len(X) < 500 else 2
        )
        binary_model.fit(X_train, bin_train)
        binary_pred = binary_model.predict(X_test)
        binary_metrics = evaluate(bin_test, binary_pred, labels=['benign', 'malicious'])

        candidates = {
            'ExtraTrees': ExtraTreesClassifier(
                n_estimators=260, class_weight='balanced', random_state=req.random_state,
                n_jobs=-1, min_samples_leaf=1 if len(X) < 500 else 2
            ),
            'RandomForest': RandomForestClassifier(
                n_estimators=220, class_weight='balanced_subsample', random_state=req.random_state,
                n_jobs=-1, min_samples_leaf=1 if len(X) < 500 else 2, max_features='sqrt'
            )
        }
        comparisons = {}
        best_name, best_model, best_score = None, None, -1.0
        all_labels = sorted(y_multi.unique().tolist())
        for name, model in candidates.items():
            model.fit(X_train, multi_train)
            pred = model.predict(X_test)
            metrics = evaluate(multi_test, pred, labels=all_labels)
            comparisons[name] = metrics
            if metrics['f1_macro'] > best_score:
                best_name, best_model, best_score = name, model, metrics['f1_macro']

        binary_model.fit(X, y_bin)
        best_model.fit(X, y_multi)

        version = datetime.now(timezone.utc).strftime('%Y.%m.%d.%H%M%S')
        source_meta = dataset_metadata(path, len(X))
        bundle = {
            'binary_model': binary_model,
            'multiclass_model': best_model,
            'feature_names': list(X.columns),
            'medians': medians.to_dict(),
            'classes': all_labels,
            'version': version,
            'algorithm': best_name,
        }
        tmp_bundle = BUNDLE_PATH.with_suffix('.joblib.tmp')
        joblib.dump(bundle, tmp_bundle, compress=3)
        tmp_bundle.replace(BUNDLE_PATH)
        artifact_hash = hashlib.sha256(BUNDLE_PATH.read_bytes()).hexdigest()
        meta = {
            'ready': True,
            'name': 'Mabeli Sentinel CICIDS2017 Detector',
            'version': version,
            'algorithm': best_name,
            'binary_algorithm': 'ExtraTrees',
            'trained_at': utcnow(),
            'dataset': str(path),
            'records': int(len(X)),
            'feature_names': list(X.columns),
            'feature_count': int(len(X.columns)),
            'classes': all_labels,
            'metrics': {
                'binary': binary_metrics,
                'multiclass': comparisons[best_name],
                'model_comparison': {
                    k: {'accuracy': v['accuracy'], 'f1_macro': v['f1_macro'], 'f1_weighted': v['f1_weighted']}
                    for k, v in comparisons.items()
                }
            },
            'artifact_hash': artifact_hash,
            **source_meta,
        }
        META_PATH.write_text(json.dumps(meta, indent=2), encoding='utf-8')
        (REPORT_DIR / f'training-{version}.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
        _bundle = bundle
        _meta = meta
        return meta


def vectorize(features: dict[str, Any]) -> pd.DataFrame:
    if not _bundle:
        raise HTTPException(409, 'No trained model is available.')
    row = {}
    normalized_lookup = {str(k).strip(): v for k, v in features.items()}
    for feature in _bundle['feature_names']:
        raw = normalized_lookup.get(feature)
        try:
            value = float(raw)
            if not np.isfinite(value):
                raise ValueError
        except (TypeError, ValueError):
            value = float(_bundle['medians'].get(feature, 0.0))
        row[feature] = value
    return pd.DataFrame([row], columns=_bundle['feature_names'])


def explain(model, row: pd.DataFrame, top_n: int = 6):
    importances = getattr(model, 'feature_importances_', None)
    if importances is None:
        return []
    indices = np.argsort(importances)[::-1][:top_n]
    return [
        {'feature': row.columns[int(i)], 'contribution': float(importances[int(i)]), 'value': float(row.iloc[0, int(i)])}
        for i in indices
    ]


def run_prediction(features: dict[str, Any]) -> dict[str, Any]:
    row = vectorize(features)
    binary = _bundle['binary_model']
    multi = _bundle['multiclass_model']
    binary_probs = binary.predict_proba(row)[0]
    bmap = {str(c): float(p) for c, p in zip(binary.classes_, binary_probs)}
    malicious_probability = bmap.get('malicious', 0.0)
    prediction = 'malicious' if malicious_probability >= 0.5 else 'benign'

    if prediction == 'benign':
        attack_type = 'BENIGN'
        confidence = bmap.get('benign', 1.0 - malicious_probability)
        probs = {'BENIGN': confidence}
    else:
        multi_probs = multi.predict_proba(row)[0]
        probs = {str(c): float(p) for c, p in zip(multi.classes_, multi_probs)}
        malicious_probs = {k: v for k, v in probs.items() if k.upper() != 'BENIGN'}
        attack_type = max(malicious_probs, key=malicious_probs.get) if malicious_probs else str(multi.predict(row)[0])
        confidence = malicious_probs.get(attack_type, malicious_probability)

    return {
        'prediction': prediction,
        'attack_type': attack_type,
        'confidence': float(confidence),
        'malicious_probability': float(malicious_probability),
        'probabilities': probs,
        'explanation': explain(multi if prediction == 'malicious' else binary, row),
        'model_version': _bundle['version'],
        'model_algorithm': _bundle['algorithm'],
    }


def chosen_benchmark_path() -> Path:
    if PUBLIC_SAMPLE_PATH.exists() and PUBLIC_SAMPLE_PATH.stat().st_size > 100_000:
        return PUBLIC_SAMPLE_PATH
    return FALLBACK_DATASET


def benchmark_df() -> pd.DataFrame:
    global _benchmark_cache
    path = chosen_benchmark_path()
    stamp = path.stat().st_mtime if path.exists() else 0
    if _benchmark_cache and _benchmark_cache[0] == str(path) and _benchmark_cache[1] == stamp:
        return _benchmark_cache[2]
    if not path.exists():
        raise HTTPException(503, 'No benchmark dataset is available')
    df = read_one(path)
    df.columns = [str(c).strip() for c in df.columns]
    label_col = next((c for c in df.columns if c.lower() == 'label'), None)
    if not label_col:
        raise HTTPException(500, 'Benchmark dataset has no Label column')
    df[label_col] = df[label_col].map(normalize_label)
    _benchmark_cache = (str(path), stamp, df)
    return df


def benchmark_records(limit: int, seed: int) -> list[dict[str, Any]]:
    df = benchmark_df().copy()
    label_col = next(c for c in df.columns if c.lower() == 'label')
    limit = min(max(1, limit), len(df), 1000)
    sample = stratified_cap(df, label_col, limit, seed) if len(df) > limit else df.sample(frac=1, random_state=seed)
    rows = []
    for _, row in sample.iterrows():
        features = {}
        for k, v in row.items():
            key = str(k).strip()
            if key.lower() in {'label', 'label_binary', 'source ip', 'destination ip', 'src ip', 'dst ip'}:
                continue
            try:
                n = float(v)
                if np.isfinite(n):
                    features[key] = n
            except (TypeError, ValueError):
                pass
        rows.append({
            'features': features,
            'ground_truth': normalize_label(row[label_col]),
            'source_ip': str(row.get('Source IP', row.get('Src IP', ''))) or None,
            'destination_ip': str(row.get('Destination IP', row.get('Dst IP', ''))) or None,
        })
    return rows


def download_public_sample() -> None:
    PUBLIC_SAMPLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PUBLIC_SAMPLE_PATH.with_suffix('.parquet.part')
    req = urllib.request.Request(PUBLIC_SAMPLE_URL, headers={'User-Agent': 'Mabeli-Sentinel/2.0'})
    with urllib.request.urlopen(req, timeout=45) as response, tmp.open('wb') as out:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
    if tmp.stat().st_size < 100_000:
        tmp.unlink(missing_ok=True)
        raise RuntimeError('Downloaded CICIDS2017 public sample is unexpectedly small')
    tmp.replace(PUBLIC_SAMPLE_PATH)


def run_remote_upgrade() -> None:
    global _bootstrap_state
    if _train_lock.locked():
        return
    _bootstrap_state = {
        **_bootstrap_state,
        'state': 'upgrading',
        'message': 'Downloading and training the 20,000-row CICIDS2017 public baseline',
        'started_at': utcnow(),
        'completed_at': None,
        'last_error': None,
    }
    try:
        if not PUBLIC_SAMPLE_PATH.exists() or PUBLIC_SAMPLE_PATH.stat().st_size < 100_000:
            download_public_sample()
        result = train_pipeline(TrainRequest(dataset_path=str(PUBLIC_SAMPLE_PATH), sample_limit=20_000, random_state=42))
        _bootstrap_state = {
            **_bootstrap_state,
            'state': 'ready',
            'message': f"Public baseline model {result['version']} is active",
            'completed_at': utcnow(),
            'last_error': None,
        }
    except Exception as exc:
        _bootstrap_state = {
            **_bootstrap_state,
            'state': 'fallback-ready' if _bundle else 'error',
            'message': 'Offline fallback remains active' if _bundle else 'Model bootstrap failed',
            'completed_at': utcnow(),
            'last_error': str(exc),
        }


def ensure_local_model() -> None:
    global _bootstrap_state
    load_bundle()
    if _bundle:
        _bootstrap_state.update({
            'state': 'ready' if _meta and _meta.get('training_scope') != 'verified-preview-fallback' else 'fallback-ready',
            'message': 'Production model loaded from disk',
            'completed_at': utcnow(),
        })
        return
    if not FALLBACK_DATASET.exists():
        raise RuntimeError('Bundled verified CICIDS2017 fallback dataset is missing')
    result = train_pipeline(TrainRequest(dataset_path=str(FALLBACK_DATASET), random_state=42))
    _bootstrap_state.update({
        'state': 'fallback-ready',
        'message': f"Offline verified fallback model {result['version']} is active",
        'completed_at': utcnow(),
    })


@app.on_event('startup')
def startup():
    ensure_local_model()
    if AUTO_BOOTSTRAP_REMOTE and (_meta or {}).get('training_scope') != 'public-20k-sample':
        threading.Thread(target=run_remote_upgrade, daemon=True, name='cicids-bootstrap').start()


@app.get('/health')
def health():
    return {
        'ok': True,
        'model_ready': _bundle is not None,
        'service': 'mabeli-sentinel-ml',
        'model_scope': (_meta or {}).get('training_scope'),
        'bootstrap': _bootstrap_state,
    }


@app.get('/model')
def model():
    if not _meta:
        return {'ready': False, 'message': 'Model is unavailable'}
    return {**_meta, 'bootstrap': _bootstrap_state}


@app.get('/bootstrap/status')
def bootstrap_status():
    return {'model': _meta, 'bootstrap': _bootstrap_state}


@app.post('/bootstrap/upgrade')
def bootstrap_upgrade():
    if _bootstrap_state.get('state') == 'upgrading':
        return _bootstrap_state
    threading.Thread(target=run_remote_upgrade, daemon=True, name='cicids-bootstrap-manual').start()
    return {**_bootstrap_state, 'state': 'starting', 'message': 'Public baseline upgrade requested'}


@app.get('/benchmark/info')
def benchmark_info():
    df = benchmark_df()
    label_col = next(c for c in df.columns if c.lower() == 'label')
    path = chosen_benchmark_path()
    return {
        'available': True,
        'path': str(path),
        'source_name': 'CICIDS2017 20,000-row public sample' if path == PUBLIC_SAMPLE_PATH else 'CICIDS2017 verified preview fallback',
        'source_url': 'https://huggingface.co/datasets/transformer112/cicids2017-ids-dataset',
        'records': int(len(df)),
        'classes': sorted(df[label_col].map(normalize_label).dropna().unique().tolist()),
        'class_counts': {str(k): int(v) for k, v in df[label_col].map(normalize_label).value_counts().to_dict().items()},
        'fallback': path == FALLBACK_DATASET,
    }


@app.get('/benchmark/sample')
def benchmark_sample(limit: int = Query(default=100, ge=1, le=1000), seed: int = Query(default=42)):
    return {'records': benchmark_records(limit, seed), 'info': benchmark_info()}


@app.post('/predict')
def predict(req: PredictRequest):
    return run_prediction(req.features)


@app.post('/predict/batch')
def predict_batch(req: BatchRequest):
    return {'results': [run_prediction(row) for row in req.records]}


@app.post('/train')
def train(req: TrainRequest):
    started = time.time()
    result = train_pipeline(req)
    result['training_seconds'] = round(time.time() - started, 2)
    return result
