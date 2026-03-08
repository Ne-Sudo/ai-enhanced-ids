import pandas as pd
from pathlib import Path

# Function to save the scored results
def save_results(results: pd.DataFrame, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_path, index=False)

# Print the top IDS alerts for the current scored batch
def display_alerts(results: pd.DataFrame, top_alerts: int = 5):
    alerts = results[results["prediction"]==1].sort_values(
        "malicious_prob", ascending= False
    )

    if alerts.empty:
        print("[ALERTS] no malicious flows detected")
        return
    
    print(f"[ALERTS] Top {min(top_alerts, len(alerts))} alerts:")
    for alert in alerts["alert"].head(top_alerts):
        print(alert)


# Build a summary row for the alert logs CSV
def build_alert_summary(results: pd.DataFrame, pcap_name: str, flow_csv_name: str) -> dict:
    flow_count = len(results)
    alert_count = int(results["prediction"].sum())
    max_prob = float(results["malicious_prob"].max()) if flow_count else 0.0

    alerts = results[results["prediction"]== 1].sort_values(
        "malicious_prob", ascending=False
    )

    if not alerts.empty:
        top = alerts.iloc[0]
        return {
            "time": pd.Timestamp.utcnow().isoformat(),
            "pcap": pcap_name,
            "flow_csv": flow_csv_name,
            "flows": flow_count,
            "alerts": alert_count,
            "max_prob": max_prob,
            "src_ip": top.get("Src IP", ""),
            "dst_ip": top.get("Dst IP", ""),
            "dst_port": top.get("Dst Port", ""),
            "protocol": top.get("Protocol", ""),
            "severity": top.get("severity", "")
        }
    
    return {
        "time": pd.Timestamp.utcnow().isoformat(),
        "pcap": pcap_name,
        "flow_csv": flow_csv_name,
        "flows": flow_count,
        "alerts": alert_count,
        "max_prob": max_prob,
        "src_ip": top.get("Src IP", ""),
        "dst_ip": top.get("Dst IP", ""),
        "dst_port": top.get("Dst Port", ""),
        "protocol": top.get("Protocol", ""),
        "severity": top.get("severity", "")
    }

#Get one alert summary row to the alert log CSV
def get_alert_log(alert_log: Path, summary_row: dict):
    alert_log.parent.mkdir(parents=True, exist_ok=True)

    row_df = pd.DataFrame([summary_row])

    if not alert_log.exists():
        row_df.to_csv(alert_log, index=False)
    else:
        row_df.to_csv(alert_log, mode="a", header=False, index=False)
