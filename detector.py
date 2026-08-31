from collections import defaultdict
from .c2_beacon import detect_beacon
from .network_scanner import detect_scans


def run_temporal_graph_engine(packet_batch: list[dict]) -> dict:
    """
    Main evaluation pipeline.
    Expected packet schema:
    [
      {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 443, "timestamp": 1720000001.2},
      ...
    ]
    """
    if not packet_batch:
        return {"status": "ok", "alerts": []}

    alerts = []

    scan_alerts = detect_scans(packet_batch)
    alerts.extend(scan_alerts)

    src_grouped_ts = defaultdict(list)
    for p in packet_batch:
        src_grouped_ts[p["src_ip"]].append(p["timestamp"])

    for src_ip, ts_list in src_grouped_ts.items():
        beacon_result = detect_beacon(ts_list)
        if beacon_result["alert"]:
            alerts.append({"src_ip": src_ip, **beacon_result})

    return {
        "status": "threat_detected" if alerts else "clean",
        "alert_count": len(alerts),
        "alerts": alerts,
    }
