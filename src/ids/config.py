# This file keeps all paths and runtime settings
from pathlib import Path

project_root = Path(r"E:\Project Portfolio\Dissertation\Final-Year-IDS")

#Runtime Folders
pcap_dir = project_root/"live"/"pcaps"
flow_dir =  project_root/"live"/"flows"
alert_dir = project_root/"live"/"alerts"
log_dir = project_root/"logs"
model_dir = project_root/"models"

#Model bundel
model_path = model_dir/"IDS_RF_v1.0"

#CICFlowMeterpath (will need to change based on where system has it installed)
cicflow_bat = Path(r"C:\Tools\CICFlowMeter-4.0\bin\cfm.bat")

#Live capture settings
interface = "5"
rotate_time = 10    #seconds per pcap
poll_time = 1.0     #loop interval
min_pcap_age = 5.0  #minimum age for the file before preprocessing
top_alerts = 5