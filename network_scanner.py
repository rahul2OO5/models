from collections import defaultdict
import numpy as np


def detect_scans(
    records: list[dict],
    horizontal_threshold: int = 15,
    vertical_threshold: int = 20,
    min_scan_rate_pps: float = 2.0,
) -> list[dict]:
    """
    Builds dynamic bipartite graphs (Src -> Dst, Src -> Port) to catch reconnaissance.
    records expected format: [{'src_ip': str, 'dst_ip': str, 'dst_port': int, 'timestamp': float}, ...]
    """
    if not records:
        return []

    src_to_dsts = defaultdict(set)
    src_dst_to_ports = defaultdict(set)
    src_timestamps = defaultdict(list)

    for r in records:
        src = r["src_ip"]
        dst = r["dst_ip"]
        port = r["dst_port"]
        ts = r.get("timestamp", 0.0)

        src_to_dsts[src].add(dst)
        src_dst_to_ports[(src, dst)].add(port)
        src_timestamps[src].append(ts)

    alerts = []

    for src, dst_set in src_to_dsts.items():
        ts_list = src_timestamps[src]
        duration = max(0.1, max(ts_list) - min(ts_list)) if len(ts_list) > 1 else 1.0
        pps = len(ts_list) / duration

        unique_dsts = len(dst_set)
        if unique_dsts >= horizontal_threshold:
            alerts.append(
                {
                    "src_ip": src,
                    "threat_type": "horizontal_reconnaissance_scan",
                    "alert": True,
                    "confidence": round(
                        min(1.0, unique_dsts / (horizontal_threshold * 2)), 3
                    ),
                    "unique_targets": unique_dsts,
                    "packet_rate_pps": round(pps, 2),
                }
            )

        for dst in dst_set:
            ports = src_dst_to_ports[(src, dst)]
            unique_ports = len(ports)
            if unique_ports >= vertical_threshold:
                alerts.append(
                    {
                        "src_ip": src,
                        "target_ip": dst,
                        "threat_type": "vertical_port_scan",
                        "alert": True,
                        "confidence": round(
                            min(1.0, unique_ports / (vertical_threshold * 2)), 3
                        ),
                        "unique_ports_scanned": unique_ports,
                        "packet_rate_pps": round(pps, 2),
                    }
                )

    return alerts
