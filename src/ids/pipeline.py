import time
from pathlib import Path

from .flow_handler import pcap_age_check, pcap_csv_conversion, find_csv, wait_for_real_csv
from .scoring import score_csv
from .alerts import save_results, display_alerts, build_alert_summary, get_alert_log
from .ips import run_ips


def run_pipeline(
    pcap_dir: Path,
    flow_dir: Path,
    alert_dir: Path,
    alert_log: Path,
    cicflow_bat: Path,
    model,
    train_features: list[str],
    threshold: float,
    poll_time: float,
    min_pcap_age: float,
    top_alerts: int,
    cleanup_after_processing: bool,
    # IPS parameters — optional so existing callers are unaffected if not passed
    ips_enabled: bool = False,
    block_log: Path | None = None,
    ip_whitelist: list[str] | None = None,
):

    processed_pcaps: set[str] = set()

    print("Live IDS pipeline running...")
    print(f"Watching PCAP folder: {pcap_dir}")
    print(f"Watching flow folder: {flow_dir}")
    if ips_enabled:
        print("[IPS] Enabled — CRITICAL and HIGH severity flows will be auto-blocked.")
    else:
        print("[IPS] Disabled — running in detection-only mode.")
    print("Interrupt to stop.\n")

    try:
        while True:

            pcaps = sorted(
                pcap_dir.glob("*.pcap"),
                key=lambda p: p.stat().st_mtime
            )

            for pcap_file in pcaps:

                if pcap_file.name in processed_pcaps:
                    continue

                if not pcap_age_check(pcap_file, min_pcap_age):
                    continue

                print(f"\n[PCAP] {pcap_file.name}")

                try:
                    pcap_csv_conversion(pcap_file, flow_dir, cicflow_bat)
                    flow_csv = find_csv(pcap_file, flow_dir)

                    if not wait_for_real_csv(flow_csv):
                        print(f"[FLOW ERROR] Real CSV still not ready: {flow_csv}")
                        continue

                except Exception as e:
                    print(f"[FLOW ERROR] {e}")
                    processed_pcaps.add(pcap_file.name)
                    continue

                try:
                    results = score_csv(
                        flow_csv=flow_csv,
                        model=model,
                        train_features=train_features,
                        # FIX: was hardcoded to 0.2, ignoring the threshold
                        # loaded from the model bundle via main.py / config.py.
                        threshold=threshold,
                    )

                    flow_count  = len(results)
                    alert_count = int(results["prediction"].sum())
                    max_prob    = float(results["malicious_prob"].max()) if flow_count else 0.0

                    print(f"[SCORE] flows={flow_count} alerts={alert_count} max_prob={max_prob:.3f}")

                    display_alerts(results, top_alerts=top_alerts)

                    # -------------------------------------------------------
                    # IPS: block source IPs for CRITICAL / HIGH severity flows
                    # -------------------------------------------------------
                    if ips_enabled and block_log is not None:
                        newly_blocked = run_ips(
                            results=results,
                            block_log=block_log,
                            pcap_name=pcap_file.name,
                            extra_whitelist=ip_whitelist
                        )
                        if newly_blocked:
                            print(f"[IPS] {newly_blocked} IP(s) newly blocked this cycle.")

                    scored_output = alert_dir / f"scored_{flow_csv.stem}.csv"
                    save_results(results, scored_output)

                    summary = build_alert_summary(results, pcap_file.name, flow_csv.name)
                    get_alert_log(alert_log, summary)

                    processed_pcaps.add(pcap_file.name)

                    # Clean up raw files now that results are saved to alert_dir.
                    # Only runs on success — errors leave files intact for debugging.
                    if cleanup_after_processing:
                        try:
                            pcap_file.unlink()
                            flow_csv.unlink()
                            print(f"[CLEANUP] Removed {pcap_file.name} and {flow_csv.name}")
                        except OSError as e:
                            print(f"[CLEANUP WARNING] Could not remove file: {e}")

                except PermissionError as e:
                    print(f"[SCORE ERROR] {e}")
                    continue

                except Exception as e:
                    print(f"[SCORE ERROR] {e}")
                    processed_pcaps.add(pcap_file.name)

            time.sleep(poll_time)

    except KeyboardInterrupt:
        print("\nStopping live IDS pipeline...")