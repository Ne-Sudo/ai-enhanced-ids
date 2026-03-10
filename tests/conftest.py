# Pytest configuration file — runs automatically before any test is collected.
#
# Purpose: add the project root to sys.path so that the src.ids package is
# importable from every test file without any per-file path hacks.
#
# After this runs, any test file can do:
#   from src.ids.preprocessing import clean_columns, normalise_features
#   from src.ids.scoring       import severity_level, score_csv
#   from src.ids.ips           import _is_private, block_ip, run_ips
#   from src.ids.flow_handler  import pcap_age_check, csv_ready
#   from src.ids.alerts        import build_alert_summary

import sys
from pathlib import Path

# Project root = the directory that contains src/, tests/, requirements.txt etc.
# __file__ here is Final-Year-IDS/tests/conftest.py
# .parent      → Final-Year-IDS/tests/
# .parent.parent → Final-Year-IDS/          ← project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))