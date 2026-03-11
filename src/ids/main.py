from .config import (
    pcap_dir,
    flow_dir,
    alert_dir,
    alert_log,
    model_path,
    cicflow_bat,
    interface,
    rotate_time,
    poll_time,
    min_pcap_age,
    top_alerts,
    cleanup_after_processing,
    # IPS
    ips_enabled,
    block_log,
    ip_whitelist,
)

from .capture import list_interfaces, start_capture, end_capture
from .scoring import load_bundle
from .pipeline import run_pipeline


def main():
    print("Available interfaces:")
    print(list_interfaces())

    bundle = load_bundle(model_path)
    model          = bundle["model"]
    train_features = bundle["features"]
    threshold      = float(bundle["threshold"])

    capture_proc = None

    try:
        capture_proc = start_capture(
            interface=interface,
            rotate_time=rotate_time,
            pcap_dir=pcap_dir
        )

        run_pipeline(
            pcap_dir=pcap_dir,
            flow_dir=flow_dir,
            alert_dir=alert_dir,
            alert_log=alert_log,
            cicflow_bat=cicflow_bat,
            model=model,
            train_features=train_features,
            threshold=threshold,
            poll_time=poll_time,
            min_pcap_age=min_pcap_age,
            top_alerts=top_alerts,
            cleanup_after_processing=cleanup_after_processing,
            # IPS
            ips_enabled=ips_enabled,
            block_log=block_log,
            ip_whitelist=ip_whitelist,
        )

    finally:
        end_capture(capture_proc)


if __name__ == "__main__":
    main()