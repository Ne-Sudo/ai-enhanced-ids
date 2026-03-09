# Handles packet captures
import subprocess
from typing import Optional
from pathlib import Path  # Added: ensure Path typing works if used externally

# List the interfaces using dumpcap and return the results as a string
def list_interfaces() -> str:
    result = subprocess.run(["dumpcap", "-D"], capture_output=True, text=True)
    return result.stdout


# Starts rotating the packet capture using dumpcap and returns the running subprocess
def start_capture(interface: str, rotate_time: int, pcap_dir: Path) -> subprocess.Popen:
    
    # Ensure the PCAP directory exists before capture starts
    pcap_dir.mkdir(parents=True, exist_ok=True)  # Added safety

    capture_cmd = [
        "dumpcap",
        "-i", interface,
        "-b", f"duration:{rotate_time}",
        "-w", str(pcap_dir / "capture.pcap")  # dumpcap will auto-rotate filenames
    ]

    print("Starting capture:")
    print(" ".join(capture_cmd))

    capture_proc = subprocess.Popen(
        capture_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    print("Capture PID:", capture_proc.pid)
    return capture_proc


# function to end the capture process
def end_capture(capture_proc: Optional[subprocess.Popen]) -> None:

    if capture_proc is None:
        return

    if capture_proc.poll() is None:
        capture_proc.terminate()
        try:
            capture_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            capture_proc.kill()

    print("Capture stopped")