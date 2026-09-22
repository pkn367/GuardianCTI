"""
AI-based risk analysis layer (project document Sections 8.4 and 8.5).

Two models, each answering a question the rule engine cannot:

  IsolationForest    unsupervised. "Which finding is unusual for this account?"
                     A single unencrypted volume in an account where everything
                     else is encrypted is more interesting than the hundredth
                     unencrypted volume in an account that never encrypts.
                     This is the anomaly detection promised in Section 8.5.

  RandomForest       supervised. Learns the mapping from finding features to an
                     analyst-assigned priority band, so the ranking can be
                     retrained on how a hospital's own security team actually
                     triaged past findings instead of staying fixed at whatever
                     weights we hard-coded.

Training data: bootstrap_training_set() synthesises a labelled corpus from the
control catalogue using the documented risk model plus noise. Replace it with
your own labelled findings, or with CICIDS2017-derived exposure features, once
you have run the collector a few times -- the feature contract stays the same.
"""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from .checks import CHECKS

log = logging.getLogger("guardian.ai")

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
SERVICES = sorted({c["service"] for c in CHECKS.values()})
AXES = ["C", "I", "A"]
PRIORITY = ["Low", "Medium", "High", "Critical"]

FEATURE_NAMES = (
    ["base_severity", "threat_pressure", "exposure", "phi", "axis_C", "axis_I", "axis_A",
     "attack_count", "evidence_size"]
    + [f"svc_{s}" for s in SERVICES]
)


def featurise(finding):
    """Finding dict -> fixed-length numeric vector. Used at train and predict time."""
    meta = CHECKS[finding["check_id"]]
    ev = finding.get("evidence", {}) or {}
    vec = [
        meta["base_severity"],
        finding.get("threat_pressure", 1.0),
        finding.get("exposure", 1.0),
        1.0 if finding.get("phi") else 0.0,
        *[1.0 if meta["impact_axis"] == a else 0.0 for a in AXES],
        len(meta["attack"]),
        min(len(json.dumps(ev, default=str)) / 100.0, 10.0),
        *[1.0 if meta["service"] == s else 0.0 for s in SERVICES],
    ]
    return np.array(vec, dtype=float)


def _label(base, pressure, exposure, phi):
    """Analyst prior used to bootstrap labels; deliberately non-linear so the
    forest has something to learn rather than a formula to memorise."""
    r = base * pressure * exposure * (1.7 if phi else 1.0)
    if phi and base >= 5:
        r *= 1.15
    if r >= 13:
        return "Critical"
    if r >= 9:
        return "High"
    if r >= 5.5:
        return "Medium"
    return "Low"


def bootstrap_training_set(n=4000, seed=42):
    rng = random.Random(seed)
    X, y = [], []
    check_ids = list(CHECKS)
    for _ in range(n):
        cid = rng.choice(check_ids)
        meta = CHECKS[cid]
        pressure = rng.uniform(1.0, 1.6)
        exposure = rng.uniform(1.0, 1.6)
        phi = rng.random() < 0.45
        fake = {
            "check_id": cid,
            "threat_pressure": pressure,
            "exposure": exposure,
            "phi": phi,
            "evidence": {"_": "x" * rng.randint(20, 400)},
        }
        X.append(featurise(fake))
        noisy = meta["base_severity"] + rng.gauss(0, 0.25)
        y.append(_label(noisy, pressure, exposure, phi))
    return np.vstack(X), np.array(y)


def train(n=4000, verbose=True):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    X, y = bootstrap_training_set(n)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    scaler = StandardScaler().fit(X_tr)
    clf = RandomForestClassifier(n_estimators=300, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(scaler.transform(X_tr), y_tr)

    iso = IsolationForest(n_estimators=200, contamination=0.12, random_state=42)
    iso.fit(scaler.transform(X_tr))

    report = classification_report(y_te, clf.predict(scaler.transform(X_te)),
                                   output_dict=True, zero_division=0)
    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_),
                         key=lambda t: -t[1])[:8]

    import joblib
    joblib.dump({"scaler": scaler, "clf": clf, "iso": iso,
                 "features": FEATURE_NAMES}, MODEL_DIR / "guardian_models.joblib")
    metrics = {
        "accuracy": round(report["accuracy"], 4),
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "per_class": {k: round(v["f1-score"], 3) for k, v in report.items()
                      if k in PRIORITY},
        "top_features": [(n, round(float(v), 4)) for n, v in importances],
        "train_size": len(X_tr),
    }
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    if verbose:
        print(json.dumps(metrics, indent=2))
    return metrics


def _load():
    import joblib
    path = MODEL_DIR / "guardian_models.joblib"
    if not path.exists():
        log.warning("No trained model found; run `python -m guardian.ai_model` first")
        return None
    return joblib.load(path)


def enrich(findings):
    """Add ai_priority, ai_confidence and anomaly_score to failed findings."""
    bundle = _load()
    fails = [f for f in findings if f["status"] == "FAIL"]
    if bundle is None or not fails:
        for f in fails:
            f.update(ai_priority=f.get("severity", "Medium"), ai_confidence=None,
                     anomaly_score=0.0, is_anomaly=False)
        return findings

    X = bundle["scaler"].transform(np.vstack([featurise(f) for f in fails]))
    proba = bundle["clf"].predict_proba(X)
    classes = list(bundle["clf"].classes_)
    preds = bundle["clf"].predict(X)
    # decision_function: negative is more anomalous. Flip and rescale to 0-100.
    raw = bundle["iso"].decision_function(X)
    lo, hi = float(raw.min()), float(raw.max())
    span = (hi - lo) or 1.0
    flags = bundle["iso"].predict(X)

    for i, f in enumerate(fails):
        f["ai_priority"] = str(preds[i])
        f["ai_confidence"] = round(float(proba[i][classes.index(preds[i])]), 3)
        f["anomaly_score"] = round(float((hi - raw[i]) / span) * 100, 1)
        f["is_anomaly"] = bool(flags[i] == -1)
        # Final rank blends the deterministic risk with what the model learned.
        rank = PRIORITY.index(f["ai_priority"]) if f["ai_priority"] in PRIORITY else 1
        f["final_rank"] = round(f.get("risk_score", 0) * 0.6
                                + rank * 6.25 * 0.3
                                + f["anomaly_score"] / 100 * 25 * 0.1, 2)
    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train()
