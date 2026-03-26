import sys
sys.path.insert(0, r"E:\Project Portfolio\Dissertation\Final-Year-IDS")

import pandas as pd
from pathlib import Path
from src.ids.scoring import load_bundle, score_csv
from src.ids.alerts import display_alerts, save_results, build_alert_summary, get_alert_log
from src.ids.ips import run_ips
from src.ids.config import (
    model_path, alert_dir, alert_log,
    ips_enabled, block_log, ip_whitelist
)

flow_csv = Path(r"E:\Project Portfolio\Dissertation\Final-Year-IDS\live\flows\capture.pcap_Flow.csv")

df = pd.read_csv(flow_csv)
df["Src IP"] = "205.174.13.89"   # attacker IP
df["Dst IP"] = "192.168.25.45"    # victim IP
df["Src Port"] = 80
df["Dst Port"] = 80
df["Protocol"] = 6
df.to_csv(flow_csv, index=False)

# --- Config debug ---
print(f"[CONFIG] ips_enabled     = {ips_enabled}")
print(f"[CONFIG] block_log       = {block_log}")
print(f"[CONFIG] ip_whitelist    = {ip_whitelist}")
print(f"[CONFIG] threshold       = ", end="")

bundle = load_bundle(model_path)
model = bundle["model"]
train_features = bundle["features"]
threshold = float(bundle["threshold"])
print(threshold)

print(f"\n[DEMO] Scoring: {flow_csv.name}")

results = score_csv(
    flow_csv=flow_csv,
    model=model,
    train_features=train_features,
    threshold=threshold,
)

flow_count  = len(results)
alert_count = int(results["prediction"].sum())
max_prob    = float(results["malicious_prob"].max()) if flow_count else 0.0

print(f"[SCORE] flows={flow_count} alerts={alert_count} max_prob={max_prob:.3f}")

# --- Severity breakdown ---
print("\n[SEVERITY BREAKDOWN]")
print(results["severity"].value_counts().to_string())

display_alerts(results, top_alerts=5)

# --- IPS debug ---
print(f"\n[IPS] ips_enabled={ips_enabled} | block_log={block_log}")

if not ips_enabled:
    print("[IPS] Skipped — ips_enabled is False in config.py")
elif block_log is None:
    print("[IPS] Skipped — block_log is None")
else:
    critical_high = results[results["severity"].isin(["CRITICAL", "HIGH"])]
    print(f"[IPS] {len(critical_high)} CRITICAL/HIGH severity flows found")

    if critical_high.empty:
        print("[IPS] No CRITICAL or HIGH flows to block — no firewall rules will be created")
    else:
        print("[IPS] Attempting to create firewall rules — run as Administrator if rules are not created")

        # only process first occurrence of each IP
        results_deduped = pd.concat([
            results[results["severity"].isin(["CRITICAL", "HIGH"])].drop_duplicates(subset=["Src IP"]),
            results[~results["severity"].isin(["CRITICAL", "HIGH"])]
        ])
        print(f"[IPS] Deduplicated to {len(results_deduped[results_deduped['severity'].isin(['CRITICAL', 'HIGH'])])} unique CRITICAL/HIGH source IP(s)")

        newly_blocked = run_ips(
            results=results_deduped,
            block_log=block_log,
            pcap_name=flow_csv.name,
            extra_whitelist=ip_whitelist
        )
        if newly_blocked:
            print(f"[IPS] {newly_blocked} IP(s) newly blocked this cycle.")
        else:
            print("[IPS] 0 IPs blocked — IPs may already be blocked, private/loopback, or whitelisted")

# --- Save results ---
scored_output = alert_dir / f"scored_{flow_csv.stem}.csv"
save_results(results, scored_output)
print(f"\n[SAVE] Scored results written to: {scored_output}")

summary = build_alert_summary(results, flow_csv.name, flow_csv.name)
get_alert_log(alert_log, summary)
print(f"[SAVE] Alert log updated: {alert_log}")

print("\n[DEMO] Complete — check dashboard for results.")