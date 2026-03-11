# Keeps all paths and runtime settings.

from pathlib import Path

project_root = Path(r"E:\Project Portfolio\Dissertation\Final-Year-IDS")

# Runtime Folders
pcap_dir    = project_root / "live" / "pcaps"
flow_dir    = project_root / "live" / "flows"
alert_dir   = project_root / "live" / "alerts"
alert_log   = alert_dir / "alerts_log.csv"
log_dir     = project_root / "logs"
model_dir   = project_root / "models"

# Model bundle
model_path = model_dir / "IDS_RF_v1.0"

# CICFlowMeter path (change based on local install location)
cicflow_bat = Path(r"C:\Tools\CICFlowMeter-4.0\bin\cfm.bat")

# Live capture settings
interface    = "5"
rotate_time  = 10    # seconds per pcap
poll_time    = 1.0   # loop interval
min_pcap_age = 5.0   # minimum file age before preprocessing
top_alerts   = 5

# Set to false to keep raw PCAPs and flow csvs after processing
cleanup_after_processing = True 

# ---------------------------------------------------------------------------
# IPS settings
# ---------------------------------------------------------------------------

# Master switch — set to False to run in IDS-only mode with no firewall changes.
ips_enabled = True

# Path to the block log CSV.
block_log = alert_dir / "block_log.csv"

# IPs that should never be auto-blocked regardless of alert severity.
# Add your gateway, DNS server, and your own machine's IP here.
ip_whitelist: list[str] = [
    # "192.168.1.1",   # example: gateway
    # "8.8.8.8",       # example: DNS
]