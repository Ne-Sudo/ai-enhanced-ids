import time
from pathlib import Path

from .flow_handler import pcap_age_check, pcap_csv_conversion, find_csv
from .scoring import score_csv
from .alerts import save_results, display_alerts, build_alert_summary, get_alert_log

def run_pipeline(pcap_dir: Path,
    flow_dir: Path,
    alert_dir: Path,
    alert_log: Path,
    cicflow_bat: Path,
    model,
    train_features: list[str],
    threshold: float,
    poll_time: float,
    min_pcap_age: float,
    top_alerts: int
):
    processed_pcaps = set()

    print("Live IDS pipeline running...")
    print(f"Watching PCAP folder: {pcap_dir}")
    print(f"Watching flow folder: {flow_dir}")
    print("Interrupt to stop.\n")

    try:
        while True:
            pcaps = sorted(pcap_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime)

            for pcap_file in pcaps:
                if pcap_file.name in processed_pcaps:
                    continue
                if not pcap_age_check(pcap_file, min_pcap_age):
                    continue
                print(f"\n[PCAP] {pcap_file.name}")

                #PCAP -> CSV conversion
                try:
                    pcap_csv_conversion(pcap_file, flow_dir, cicflow_bat)
                    flow_csv = find_csv(pcap_file, flow_dir)
                    print(f"[FLOW] {flow_csv.name}")
                
                except Exception as e:
                    print(f"[FLOW ERROR] {e}")
                    processed_pcaps.add(pcap_file.name)
                    continue

                #CSV Scoring
                try:
                    results = score_csv(flow_csv, model, train_features, threshold = 0.2)
                    flow_count = len(results)
                    alert_count = int(results["prediction"].sum())
                    max_prob = float(results["malicious_prob"].max()) if flow_count else 0.0
                    print(f"[SCORE] flows={flow_count} alerts={alert_count} max_prob={max_prob:.3f}")

                    display_alerts(results, top_alerts=top_alerts)

                    scored_output = alert_dir / f"scored_{flow_csv.stem}.csv"
                    save_results(results, scored_output)

                    summary = build_alert_summary(results, pcap_file.name, flow_csv.name)
                    get_alert_log(alert_log, summary)
                
                except Exception as e:
                    print(f"[SCORE ERROR] {e}")

                processed_pcaps.add(pcap_file.name)
            time.sleep(poll_time)
        
    except KeyboardInterrupt:
        print("\nStopping live IDS pipeline...")
