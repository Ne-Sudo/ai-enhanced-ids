import pandas as pd
from pathlib import Path

# Save the full scored dataframe.
def save_results(results: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_path, index=False)

# Print the top IDS alerts for the current scored batch.
def display_alerts(results: pd.DataFrame, top_alerts: int = 5) -> None:
    alerts = results[results["prediction"] == 1].sort_values(
        "malicious_prob",
        ascending=False
    )

    if alerts.empty:
        print("[ALERTS] no malicious flows detected")
        return

    print(f"[ALERTS] Top {min(top_alerts, len(alerts))} alerts:")
    for alert in alerts["alert"].head(top_alerts):
        print(alert)

# Build one summary row for the alert log CSV.
def build_alert_summary(results: pd.DataFrame, pcap_name: str, flow_csv_name: str) -> dict:
    flow_count = len(results)
    alert_count = int(results["prediction"].sum())
    max_prob = float(results["malicious_prob"].max()) if flow_count else 0.0

    alerts = results[results["prediction"] == 1].sort_values(
        "malicious_prob",
        ascending=False
    )

    top = alerts.iloc[0] if not alerts.empty else None

    return {
        "time": pd.Timestamp.utcnow().isoformat(),
        "pcap": pcap_name,
        "flow_csv": flow_csv_name,
        "flows": flow_count,
        "alerts": alert_count,
        "max_prob": max_prob,
        "src_ip": top.get("Src IP", "") if top is not None else "",
        "dst_ip": top.get("Dst IP", "") if top is not None else "",
        "dst_port": top.get("Dst Port", "") if top is not None else "",
        "protocol": top.get("Protocol", "") if top is not None else "",
        "severity": top.get("severity", "") if top is not None else ""
    }

# Append one alert summary row to the alert log CSV.
def get_alert_log(alert_log: Path, summary_row: dict) -> None:
    alert_log.parent.mkdir(parents=True, exist_ok=True)

    row_df = pd.DataFrame([summary_row])

    if not alert_log.exists():
        row_df.to_csv(alert_log, index=False)
    else:
        row_df.to_csv(alert_log, mode="a", header=False, index=False)
