# AI-Enhanced Network Intrusion Detection and Prevention System

A machine learning-based Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) that uses Random Forest classification to detect malicious network traffic and autonomously block threats via Windows Firewall integration.

---

## Overview

This project implements a real-time network monitoring pipeline that:

1. **Captures** live network traffic using `dumpcap` (packet rotation every 10 seconds)
2. **Extracts** network flows via CICFlowMeter (converts PCAP → CSV)
3. **Preprocesses** flow data with feature normalization and missing-value handling
4. **Scores** flows using a trained Random Forest classifier
5. **Classifies** threats by severity (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
6. **Blocks** source IPs autonomously for CRITICAL/HIGH threats via Windows Firewall rules
7. **Visualizes** alerts and attack patterns on a SOC-style dashboard

### Key Results

- **Precision:** 0.98
- **Recall:** 0.64 (Friday DDoS holdout, unseen during training)
- **F1 Score:** 0.77
- **ROC-AUC:** 0.95
- **False Positive Rate:** 1.43%
- **Model:** Random Forest (IDS_RF_v1.0)

---

## Installation

### Prerequisites

- **OS:** Windows 10+ (PowerShell required for IPS firewall integration)
- **Python:** 3.10+
- **Tools:** 
  - Wireshark/dumpcap (packet capture)
  - CICFlowMeter 4.0 (flow extraction)
  - TShark (optional, for packet analysis)

### Python Dependencies

```bash
pip install -r requirements.txt
```

Core packages:
- `scikit-learn` — Random Forest, preprocessing
- `pandas` — Data handling
- `joblib` — Model serialization
- `streamlit` — Dashboard UI
- `pyvis` — Network graph visualization
- `networkx` — Graph operations

### Setup Steps

1. **Install Wireshark** (includes dumpcap)
   ```bash
   # Windows: Download from https://www.wireshark.org/download/
   # Or via Chocolatey:
   choco install wireshark
   ```

2. **Install CICFlowMeter**
   - Download from: https://www.unb.ca/cic/datasets/cicflowmeter.html
   - Extract to local directory (e.g., `C:\Tools\CICFlowMeter-4.0`)

3. **Update config.py**
   - Set `cicflow_bat` to your CICFlowMeter installation path
   - Set `project_root` to your working directory
   - Adjust `interface` (run `dumpcap -D` to list available interfaces)
   - Configure `ip_whitelist` with internal/trusted IPs to never block

4. **Load the model bundle**
   - Place pre-trained model at: `models/IDS_RF_v1.0`
   - Bundle structure:
     ```
     {
       "model": <sklearn.ensemble.RandomForestClassifier>,
       "features": [list of 84 feature names],
       "threshold": 0.20  # Probability threshold for positive prediction
     }
     ```

---

## Usage

### Run the Live IDS Pipeline

```bash
python -m src.ids.main
```

This will:
1. List available network interfaces
2. Load the trained model bundle
3. Start packet capture on the configured interface
4. Begin monitoring the PCAP and flow directories
5. Score flows and log alerts in real-time
6. Block malicious IPs (if IPS is enabled) via Windows Firewall
7. Run indefinitely until interrupted (Ctrl+C)

**Output directories created:**
- `live/pcaps/` — Captured PCAP files (auto-rotated)
- `live/flows/` — CICFlowMeter-generated flow CSVs
- `live/alerts/` — Scored results and alert log
  - `alerts_log.csv` — Summary of each PCAP batch
  - `block_log.csv` — IPs auto-blocked by IPS module
  - `attack_map.html` — Network graph visualization
- `logs/` — System logs

### View the Dashboard

In a separate terminal:

```bash
streamlit run src/ids/dashboard.py
```

Open `http://localhost:8501` in your browser if it does not open automatically.

The dashboard displays:
- **System Status:** Pipeline state, model, threshold
- **Metrics:** Flows processed, alerts detected, max threat probability
- **Flow Timeline:** Flows/minute over time
- **Alert Severity:** Distribution of CRITICAL/HIGH/MEDIUM/LOW/SAFE
- **Active Threats:** Most recent alerts with severity color-coding
- **Top Alerts:** Ranked by malicious probability
- **Network Attack Map:** Interactive graph of source → destination connections
- **Alert Log:** Full CSV of all scored batches
- **IPS Block Log:** History of auto-blocked IPs

---

## Configuration

Edit `src/ids/config.py`:

```python
# Paths
project_root = Path(r"E:\Project Portfolio\Dissertation\Final-Year-IDS")
pcap_dir = project_root / "live" / "pcaps"
flow_dir = project_root / "live" / "flows"
alert_dir = project_root / "live" / "alerts"
model_path = model_dir / "IDS_RF_v1.0"
cicflow_bat = Path(r"C:\Tools\CICFlowMeter-4.0\bin\cfm.bat")

# Capture settings
interface = "5"                 # Network interface number (dumpcap -D to list)
rotate_time = 10                # Seconds per PCAP file
poll_time = 1.0                 # Loop interval (seconds)
min_pcap_age = 5.0              # Min age before preprocessing (seconds)
top_alerts = 5                  # Display top N alerts

# Cleanup
cleanup_after_processing = True # Delete raw PCAP/CSV after scoring

# IPS settings
ips_enabled = True              # switch for auto-blocking
ip_whitelist = [
    # "192.168.1.1",            # Gateway (example)
    # "8.8.8.8",                # DNS (example)
]
```

---

## Module Reference

### `main.py`
Entry point. Loads the model bundle, starts packet capture, and runs the pipeline loop.

### `capture.py`
Handles packet capture using dumpcap:
- `list_interfaces()` — Show available network interfaces
- `start_capture()` — Start rotating PCAP capture
- `end_capture()` — Gracefully stop capture subprocess

### `flow_handler.py`
Manages PCAP → CSV conversion and file readiness checks:
- `pcap_age_check()` — Ensure file is stable before processing
- `pcap_csv_conversion()` — Call CICFlowMeter to extract flows
- `find_csv()` — Locate the generated flow CSV
- `csv_ready()` — Verify CSV is accessible and ready
- `wait_for_real_csv()` — Poll for CSV with timeout

### `preprocessing.py`
Normalizes live CICFlowMeter output to match training feature names:
- `clean_columns()` — Strip whitespace from column names
- `extract_metadata()` — Preserve non-model columns (IPs, ports, etc.)
- `normalise_features()` — Rename, convert to numeric, median-impute, reindex to training feature set

### `scoring.py`
Applies the model to normalized flows:
- `load_bundle()` — Deserialize model, features, and threshold from disk
- `severity_level()` — Map probability → severity label (CRITICAL/HIGH/MEDIUM/LOW/SAFE)
- `build_alert()` — Format human-readable alert strings
- `score_csv()` — Full pipeline: load, preprocess, predict, classify severity

**Threshold logic:** `prediction = 1 if probability >= threshold else 0`

### `ips.py`
Intrusion Prevention System — Windows Firewall integration:
- `block_ip()` — Create inbound + outbound firewall rules (PowerShell)
- `unblock_ip()` — Remove firewall rules
- `is_blocked()` — Check if rule already exists (avoid duplicates)
- `log_block()` — Append block event to CSV
- `run_ips()` — Iterate alerts, block CRITICAL/HIGH sources, respect whitelist

**Private IP handling:** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 are never auto-blocked.

### `alerts.py`
Alert logging and display:
- `display_alerts()` — Print top malicious flows to console
- `save_results()` — Write full scored CSV to output directory
- `build_alert_summary()` — Create one-row summary per PCAP batch
- `get_alert_log()` — Append summary to alerts_log.csv

### `pipeline.py`
Main event loop:
1. Poll `pcap_dir` for new PCAPs
2. Verify PCAP age (avoid incomplete files)
3. Convert to CSV via CICFlowMeter
4. Score flows with model
5. Run IPS if enabled
6. Log alerts
7. Optionally clean up raw files
8. Repeat every `poll_time` seconds

---

## Model Details

### Training Data
- **Dataset:** CICIDS-2017 (Monday–Friday morning, excluding Friday DDoS)
- **Features:** 84 network flow statistics (packet counts, byte rates, flags, inter-arrival times, etc.)
- **Classes:** Binary (benign=0, malicious=1)
- **Imbalance:** Handled via class weighting

### Evaluation Holdout
- **Test set:** Friday DDoS attack (unseen during training)
- **Results:**
  - Precision: 0.98 (low false positive rate)
  - Recall: 0.64 (distribution shift — new attack type)
  - F1: 0.77
  - ROC-AUC: 0.95


---

## Severity Classification

Threats are classified by probability:

| Probability | Severity | IPS Action |
|-------------|----------|-----------|
| > 0.80     | CRITICAL | Block (if enabled) |
| > 0.50     | HIGH     | Block (if enabled) |
| > 0.25     | MEDIUM   | Log only |
| ≥ threshold| LOW      | Log only |
| < threshold| SAFE     | —         |

**Default threshold:** 0.2

---

## Limitations & Future Work

### Known Limitations
1. **Dataset generalization:** Trained on CICIDS-2017; may not detect novel 2024+ attack patterns
2. **CICFlowMeter dependency:** Requires external tool; TShark was evaluated as alternative but not integrated due to time constraints
3. **Windows-only IPS:** Firewall integration is PowerShell-based (Windows only); Linux/macOS would need iptables/pfctl equivalents
4. **Live capture constraints:** Requires administrative privileges; interface selection is manual
5. **Class imbalance:** Training data heavily benign; rare attacks may be underrepresented

### Future Enhancements
- **Cross-platform IPS:** Implement iptables/pfctl backends for Linux/macOS
- **Incremental learning:** Retrain periodically on new labelled data
- **Alert tuning:** Adaptive thresholds per attack type

---

## Troubleshooting

### PCAP Not Being Created
- Verify interface is correct: `dumpcap -D`
- Check user has network capture privileges (may need admin)
- Confirm firewall isn't blocking dumpcap

### CICFlowMeter Fails
- Verify `cicflow_bat` path in config.py is correct
- Ensure Java is installed (CICFlowMeter requirement)
- Check PCAP file isn't corrupted: `dumpcap -i <interface> -c 100 -w test.pcap`

### Model Load Error
- Confirm model bundle exists at `models/IDS_RF_v1.0`
- Verify bundle contains keys: `model`, `features`, `threshold`
- Re-pickle model if corrupted: `joblib.dump({...}, model_path)`

### Dashboard Won't Connect
- Ensure Streamlit is installed: `pip install streamlit`
- Check port 8501 isn't in use: `netstat -an | findstr 8501`
- Verify alert_log exists (empty dashboard on first run is normal)

### IPS Blocking Trusted IPs
- Add IP to `ip_whitelist` in config.py
- Or disable IPS: `ips_enabled = False`
- Manually unblock: `powershell -Command "Remove-NetFirewallRule -DisplayName 'IDS_BLOCK_<ip_addr>_IN'"`

---

## References

**Core Papers:**
- Breiman, L. (2001). Random Forests. *Machine Learning*, 45(1), 5–32.
- Scarfone, K., & Mell, P. (2007). Guide to Intrusion Detection and Prevention Systems (IDPS). NIST SP 800-94.
- Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. In *4th ICISSP* (pp. 108–116).
- Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. In *IEEE S&P* (pp. 305–316).

**Dataset:**
- CICIDS-2017: https://www.unb.ca/cic/datasets/ids-2017.html

**Tools:**
- Wireshark: https://www.wireshark.org/
- CICFlowMeter: https://www.unb.ca/cic/datasets/cicflowmeter.html
- Streamlit: https://streamlit.io/

---

## License & Attribution

**Student Project:** Brunel University London, BSc Computer Science Final Year  
**Author:** Nezar (2226647) 

This project is provided for educational purposes. Use in production should be accompanied by rigorous security testing and validation.

---

## Contact & Support

For questions about this project, please feel free to contact me at my email nezarr.chaham@proton.me

---

**Last updated:** 26 March 2026
