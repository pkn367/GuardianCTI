"""
Medical IoT device-layer intrusion detection.

Companion to guardian/ai_model.py, not a replacement for it. The two models
answer different questions on different feature spaces, and neither can
substitute for the other:

  guardian.ai_model   ranks AWS control-plane misconfigurations found by the
                       collector (S3 policy, IAM, security groups...). Trained
                       on a bootstrapped label set (see that file's docstring).

  guardian.iot_model   classifies device-layer network traffic from bedside
                       medical sensors (ECG, blood pressure, SpO2, temperature)
                       as normal telemetry or an attack. Trained on
                       WUSTL-EHMS-2020 (Hady et al., 2020), a published dataset
                       of real captures from a physical medical IoT testbed
                       with attacks injected and labelled by the dataset's
                       authors -- not self-generated.

There is no live medical IoT device feed inside the AWS Learner Lab, so this
module is evaluated and demonstrated against a slice of the dataset's own
test rows, held out at training time and never used for fitting. The metrics
this module reports are therefore real measurements, not a bootstrap.

    python -m guardian.iot_model              # train, prints metrics
    python -m guardian.iot_model --sample 20   # score 20 held-out rows, print predictions

Outputs (all under models/, alongside ai_model.py's guardian_models.joblib):
    models/iot_intrusion_model.joblib   trained model + feature/encoder contract
    models/iot_metrics.json             accuracy, ROC-AUC, confusion matrix, etc.
    models/iot_demo_holdout.csv         test-split rows, saved for later demo runs
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

log = logging.getLogger("guardian.iot")

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "wustl_ehms_2020.csv"
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODEL_DIR / "iot_intrusion_model.joblib"
HOLDOUT_PATH = MODEL_DIR / "iot_demo_holdout.csv"
RANDOM_STATE = 42

# Identifier/metadata columns dropped before training -- not predictive signal.
DROP_COLS_CANDIDATES = [
    "Dir", "Flgs", "SrcAddr", "DstAddr", "SrcMac", "DstMac",
    "StartTime", "LastTime", "SrcId", "DstId", "Attack Category",
]
LABEL_COL_CANDIDATES = ["Label", "label", "Attack Category", "class"]


def _prepare(df: pd.DataFrame):
    label_col = next((c for c in LABEL_COL_CANDIDATES if c in df.columns), None)
    if label_col is None:
        raise ValueError(f"Could not find a label column. Columns present: {list(df.columns)}")
    drop_cols = [c for c in DROP_COLS_CANDIDATES if c in df.columns and c != label_col]
    feats = df.drop(columns=drop_cols, errors="ignore")
    X = feats.drop(columns=[label_col])
    y = feats[label_col]
    return X, y, label_col


def train(data_path=DATA_PATH, n_estimators=200, verbose=True):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Loading %s", data_path)
    df = pd.read_csv(data_path)
    X, y, label_col = _prepare(df)

    label_encoder = None
    if y.dtype == object:
        label_encoder = LabelEncoder()
        y = pd.Series(label_encoder.fit_transform(y), index=y.index)

    cat_encoders = {}
    for col in X.select_dtypes(include=["object"]).columns:
        enc = LabelEncoder()
        X[col] = enc.fit_transform(X[col].astype(str))
        cat_encoders[col] = enc

    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median(numeric_only=True))
    feature_names = list(X.columns)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    # Save the untouched original rows behind the test split for later demo
    # runs, so `--sample` always scores data the model never trained on.
    df.loc[X_te.index].to_csv(HOLDOUT_PATH, index=False)

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    log.info("Training RandomForest on %d rows, %d features", len(X_tr), len(feature_names))
    model.fit(X_tr, y_tr)

    y_pred = model.predict(X_te)
    y_proba = model.predict_proba(X_te)[:, 1] if len(np.unique(y)) == 2 else None
    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    attack_key = "1" if "1" in report else ("1.0" if "1.0" in report else None)
    importances = sorted(zip(feature_names, model.feature_importances_), key=lambda t: -t[1])[:10]

    metrics = {
        "dataset": "WUSTL-EHMS-2020",
        "source": "Hady et al. 2020, real medical IoT testbed traffic",
        "rows_total": int(len(df)),
        "train_size": int(len(X_tr)),
        "test_size": int(len(X_te)),
        "accuracy": round(accuracy_score(y_te, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_te, y_proba), 4) if y_proba is not None else None,
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "attack_precision": round(report[attack_key]["precision"], 4) if attack_key else None,
        "attack_recall": round(report[attack_key]["recall"], 4) if attack_key else None,
        "confusion_matrix": confusion_matrix(y_te, y_pred).tolist(),
        "top_features": [(n, round(float(v), 4)) for n, v in importances],
    }

    bundle = {
        "model": model,
        "feature_names": feature_names,
        "categorical_encoders": cat_encoders,
        "label_encoder": label_encoder,
        "label_col": label_col,
    }
    import joblib
    joblib.dump(bundle, MODEL_PATH)
    (MODEL_DIR / "iot_metrics.json").write_text(json.dumps(metrics, indent=2))
    if verbose:
        print(json.dumps(metrics, indent=2))
    return metrics


def _load():
    import joblib
    if not MODEL_PATH.exists():
        log.warning("No trained IoT model found; run `python -m guardian.iot_model` first")
        return None
    return joblib.load(MODEL_PATH)


def score_dataframe(df: pd.DataFrame, bundle=None):
    """Score rows shaped like the training CSV. Returns (predictions, attack_probability, y_true)."""
    bundle = bundle or _load()
    if bundle is None:
        return None, None, None
    X, y_true, _ = _prepare(df.copy())
    for col, enc in bundle["categorical_encoders"].items():
        if col in X.columns:
            known = set(enc.classes_)
            X[col] = X[col].astype(str).map(lambda v: v if v in known else enc.classes_[0])
            X[col] = enc.transform(X[col])
    X = X.reindex(columns=bundle["feature_names"], fill_value=0)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    model = bundle["model"]
    preds = model.predict(X)
    proba = model.predict_proba(X)[:, 1] if len(model.classes_) == 2 else None
    return preds, proba, y_true


def demo_sample(n=15, seed=7):
    """Score n rows drawn from the saved, genuinely-unseen test-split holdout.
    Used for a live scoring demo during the review without needing a real
    device feed."""
    bundle = _load()
    if bundle is None or not HOLDOUT_PATH.exists():
        return None
    df = pd.read_csv(HOLDOUT_PATH)
    sample = df.sample(n=min(n, len(df)), random_state=seed)
    preds, proba, y_true = score_dataframe(sample, bundle)
    if preds is None:
        return None
    rows = []
    for i in range(len(sample)):
        actual = int(y_true.iloc[i]) if y_true is not None else None
        predicted = int(preds[i])
        rows.append({
            "actual": actual,
            "predicted": predicted,
            "attack_probability": round(float(proba[i]), 3) if proba is not None else None,
            "correct": (actual == predicted) if actual is not None else None,
        })
    return rows


def summary_for_dashboard(sample_size=15):
    """Compact, JSON-safe bundle for pipeline.py to fold into findings.json /
    dashboard/data.js. Returns None if the model hasn't been trained yet."""
    metrics_path = MODEL_DIR / "iot_metrics.json"
    if not metrics_path.exists():
        return None
    metrics = json.loads(metrics_path.read_text())
    return {"metrics": metrics, "sample_predictions": demo_sample(n=sample_size)}


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="Medical IoT intrusion-detection model")
    p.add_argument("--sample", type=int, default=0,
                   help="score N held-out rows and print predictions instead of training")
    args = p.parse_args()
    if args.sample:
        rows = demo_sample(args.sample)
        if rows is None:
            print("No trained model / holdout file found. Run without --sample first.")
        else:
            for r in rows:
                print(r)
    else:
        train()
