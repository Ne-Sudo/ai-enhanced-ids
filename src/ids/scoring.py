import joblib
import pandas as pd
from pathlib import Path  # FIX: missing import

from .preprocessing import clean_columns, extract_metadata, normalise_features


def load_bundle(model_path: Path) -> dict:
    return joblib.load(model_path)


def severity_level(probability: float, threshold: float):
    if probability > 0.80:
        return "CRITICAL"
    elif probability > 0.50:
        return "HIGH"
    elif probability > 0.25:
        return "MEDIUM"
    elif probability > threshold:
        return "LOW"

    return "SAFE"


def build_alert(row: pd.Series, probability: float):
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

    alerts = []

    for i, row in results.iterrows():

        if results.loc[i, "prediction"] == 1:
            alerts.append(build_alert(row, results.loc[i, "malicious_prob"]))
        else:
            alerts.append("")

    results["alert"] = alerts

    return results