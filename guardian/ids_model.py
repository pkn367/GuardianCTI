"""
Real-dataset AI model, trained on the WUSTL-EHMS-2020 dataset (Hady et al.,
2020) -- network flow and patient biometric data captured from a real
Enhanced Healthcare Monitoring System testbed, with man-in-the-middle
(spoofing and data-injection) attacks labelled.

This is deliberately kept SEPARATE from ai_model.py. That file ranks
*cloud configuration findings* (open port, missing encryption, and so on) --
there is no public dataset of labelled cloud misconfigurations, so it will
keep using the documented risk-formula bootstrap, and that is a defensible,
industry-normal choice to say out loud if asked.

This file solves a different, complementary problem: detecting attacks in
*network traffic* -- exactly the kind of data the CICIDS/CICIoMT-style
datasets your course listed actually contain. It answers "can a real,
published, labelled dataset train a working classifier", which is what was
asked for.

Run:
    python -m guardian.ids_model --csv data/wustl_ehms_2020.csv

Output:
    models/ids_model.joblib      the trained classifier
    models/ids_metrics.json      accuracy, F1, confusion matrix, feature importance
"""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                              confusion_matrix, f1_score, precision_score,
                              recall_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


def _split_s3_uri(uri: str):
    """'s3://bucket/key/path.csv' -> ('bucket', 'key/path.csv')"""
    assert uri.startswith("s3://"), f"not an s3 uri: {uri}"
    rest = uri[len("s3://"):]
    bucket, _, key = rest.partition("/")
    return bucket, key


def read_csv_any(path_or_uri: str, region: str = "us-east-1") -> pd.DataFrame:
    """Read a CSV from a local path, or straight out of S3 with no local
    copy ever touching disk, if given an s3://bucket/key.csv URI."""
    if path_or_uri.startswith("s3://"):
        import boto3
        bucket, key = _split_s3_uri(path_or_uri)
        print(f"Reading s3://{bucket}/{key} ...")
        s3 = boto3.client("s3", region_name=region)
        obj = s3.get_object(Bucket=bucket, Key=key)
        return pd.read_csv(io.BytesIO(obj["Body"].read()), low_memory=False)
    return pd.read_csv(path_or_uri, low_memory=False)


def upload_to_s3(local_path: Path, s3_uri_prefix: str, region: str = "us-east-1"):
    """Push a local file (the trained model or the metrics JSON) up into the
    same S3 bucket the dataset came from, under s3_uri_prefix."""
    import boto3
    bucket, prefix = _split_s3_uri(s3_uri_prefix)
    key = f"{prefix.rstrip('/')}/{local_path.name}"
    s3 = boto3.client("s3", region_name=region)
    s3.upload_file(str(local_path), bucket, key)
    print(f"Uploaded {local_path.name} -> s3://{bucket}/{key}")

# Columns that identify a specific device/session rather than describing
# traffic behaviour. Keeping these would let the model "cheat" by memorising
# an address instead of learning an attack pattern -- this is called label
# leakage. We drop anything that looks like an identifier, a MAC/IP address,
# or a raw timestamp. The WUSTL authors used the Source MAC address to build
# the label in the first place, so leaving it in would make the result look
# artificially perfect while learning nothing real.
LEAKY_NAME_HINTS = ("mac", "addr", "ip", "time", "date", "id", "flgs",
                     "index", "unnamed")

LABEL_CANDIDATES = ["Label", "label", "Attack Category", "AttackCategory",
                    "Traffic Category", "class", "Class", "Attack"]


def _find_label_column(df: pd.DataFrame) -> str:
    for cand in LABEL_CANDIDATES:
        if cand in df.columns:
            return cand
    # Fall back: the last column is the label in most releases of this dataset.
    print(f"Could not find a known label column name automatically.\n"
          f"Available columns: {list(df.columns)}\n"
          f"Using the last column '{df.columns[-1]}' as the label -- "
          f"edit LABEL_CANDIDATES above if this is wrong.")
    return df.columns[-1]


def load_and_prepare(csv_path: str, region: str = "us-east-1"):
    df = read_csv_any(csv_path, region=region)
    print(f"Loaded {csv_path}: {df.shape[0]} rows, {df.shape[1]} columns")

    label_col = _find_label_column(df)
    y_raw = df[label_col]

    drop_cols = [c for c in df.columns
                if c == label_col
                or any(hint in c.lower() for hint in LEAKY_NAME_HINTS)]
    X = df.drop(columns=drop_cols)

    # Keep numeric columns only; a handful of stray text columns commonly
    # sneak into IoT capture exports (e.g. protocol names as strings).
    X = X.select_dtypes(include=[np.number]).copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(X.median(numeric_only=True))

    print(f"Dropped as identifiers/leakage: {drop_cols}")
    print(f"Using {X.shape[1]} numeric features: {list(X.columns)}")

    le = LabelEncoder()
    y = le.fit_transform(y_raw.astype(str))
    print(f"Label classes: {dict(zip(le.classes_, range(len(le.classes_))))}")
    print(f"Class balance: {pd.Series(y_raw).value_counts().to_dict()}")

    return X, y, le, label_col


def train(csv_path: str, region: str = "us-east-1", upload_prefix: str | None = None):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    X, y, le, label_col = load_and_prepare(csv_path, region=region)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, random_state=42,
        stratify=y if len(set(y)) > 1 else None)

    scaler = StandardScaler().fit(X_tr)
    clf = RandomForestClassifier(n_estimators=300, max_depth=14,
                                 random_state=42, n_jobs=-1,
                                 class_weight="balanced")
    clf.fit(scaler.transform(X_tr), y_tr)

    preds = clf.predict(scaler.transform(X_te))
    acc = accuracy_score(y_te, preds)
    f1 = f1_score(y_te, preds, average="macro")
    prec = precision_score(y_te, preds, average="macro", zero_division=0)
    rec = recall_score(y_te, preds, average="macro", zero_division=0)
    cm = confusion_matrix(y_te, preds).tolist()
    report = classification_report(y_te, preds, target_names=[str(c) for c in le.classes_],
                                   output_dict=True, zero_division=0)

    importances = sorted(zip(X.columns, clf.feature_importances_),
                         key=lambda t: -t[1])[:10]

    metrics = {
        "dataset": "WUSTL-EHMS-2020",
        "label_column": label_col,
        "classes": list(le.classes_),
        "train_rows": len(X_tr),
        "test_rows": len(X_te),
        "features_used": X.shape[1],
        "accuracy": round(float(acc), 4),
        "macro_f1": round(float(f1), 4),
        "macro_precision": round(float(prec), 4),
        "macro_recall": round(float(rec), 4),
        "confusion_matrix": cm,
        "confusion_matrix_labels": [str(c) for c in le.classes_],
        "per_class": {k: {kk: round(vv, 3) for kk, vv in v.items()}
                      for k, v in report.items() if k in [str(c) for c in le.classes_]},
        "top_features": [(n, round(float(v), 4)) for n, v in importances],
    }

    import joblib
    joblib.dump({"scaler": scaler, "clf": clf, "label_encoder": le,
                "feature_names": list(X.columns)}, MODEL_DIR / "ids_model.joblib")
    (MODEL_DIR / "ids_metrics.json").write_text(json.dumps(metrics, indent=2))

    print("\n" + "=" * 60)
    print(f"Accuracy      : {metrics['accuracy']*100:.2f}%")
    print(f"Macro F1      : {metrics['macro_f1']*100:.2f}%")
    print(f"Macro Recall  : {metrics['macro_recall']*100:.2f}%")
    print(f"Top features  : {[n for n,_ in importances[:5]]}")
    print(f"Confusion matrix ({metrics['confusion_matrix_labels']}):")
    for row in cm:
        print("  ", row)
    print("=" * 60)
    print(f"\nSaved model  -> {MODEL_DIR/'ids_model.joblib'}")
    print(f"Saved metrics -> {MODEL_DIR/'ids_metrics.json'}")

    if upload_prefix:
        upload_to_s3(MODEL_DIR / "ids_model.joblib", upload_prefix, region=region)
        upload_to_s3(MODEL_DIR / "ids_metrics.json", upload_prefix, region=region)
        print(f"\nModel and metrics are now stored in AWS at {upload_prefix}/ "
              f"-- nothing further needs to stay only on this laptop.")
    return metrics


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train IDS model on a real IoMT dataset, "
                                            "reading the dataset from S3")
    p.add_argument("--csv", default="data/wustl_ehms_2020.csv",
                   help="Local path OR s3://bucket/key.csv")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--upload-to", default=None,
                   help="s3://bucket/prefix to upload the trained model and "
                        "metrics back into AWS after training, e.g. "
                        "s3://guardian-ml-data-723482743663/models")
    args = p.parse_args()
    train(args.csv, region=args.region, upload_prefix=args.upload_to)
