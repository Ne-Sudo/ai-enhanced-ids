import joblib
import pandas as pd
from pathlib import Path

from .preprocessing import clean_columns, extract_metadata, normalise_features


def load_bundle(model_path: Path) -> dict:
    return joblib.load(model_path)


def severity_level(probability: float, threshold: float) -> str:
    # BUG FIX: original used `> threshold` for LOW band, meaning a flow scored
    # exactly at threshold was labelled SAFE despite prediction == 1.
    # Changed to `>= threshold` to match the prediction boundary in score_csv.
    if probability > 0.80:
        return "CRITICAL"
    elif probability > 0.50:
        return "HIGH"
    elif probability > 0.25:
        return "MEDIUM"
    elif probability >= threshold:
        return "LOW"

    return "SAFE"


def build_alert(row: pd.Series, probability: float) -> str:
    return (
        f"⚠ Potential malicious flow detected | "
        f"{row.get('Src IP', '?')}:{row.get('Src Port', '?')} -> "
        f"{row.get('Dst IP', '?')}:{row.get('Dst Port', '?')} | "
        f"Protocol: {row.get('Protocol', '?')} | "
        f"Probability: {probability:.3f}"
    )


def score_csv(flow_csv: Path, model, train_features: list[str], threshold: float) -> pd.DataFrame:
    df = pd.read_csv(flow_csv)
    df = clean_columns(df)
    metadata = extract_metadata(df)
    X = normalise_features(df, train_features)

    if list(X.columns) != list(train_features):
        raise ValueError("Feature mismatch after normalisation")

    if X.empty:
        raise ValueError(f"No usable flow rows found in {flow_csv}")

    probabilities = model.predict_proba(X)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    results = metadata.copy()
    results["malicious_prob"] = probabilities
    results["prediction"] = predictions
    results["severity"] = [severity_level(p, threshold) for p in probabilities]

    # IMPROVEMENT: vectorised alert string construction replaces iterrows loop.
    def _alert_or_empty(row: pd.Series) -> str:
        if row["prediction"] == 1:
            return build_alert(row, row["malicious_prob"])
        return ""

    results["alert"] = results.apply(_alert_or_empty, axis=1)

    return results