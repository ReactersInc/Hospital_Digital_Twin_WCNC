#!/usr/bin/env python3
"""
External ICU-only DDoS Engine (PyShark-based)

- Captures on 'any' interface
- Filters traffic to ICU IPs only
- Computes per-window metrics
- Sends alerts to Ryu via REST
- No file storage (terminal only)
"""

import pyshark
import time
import math
import json
import requests
from collections import defaultdict

# ---------------- CONFIG ---------------- #

ICU_IPS = {
    "10.0.1.11",
    "10.0.1.12",
    "10.0.1.13",
    "10.0.1.14",
    "10.0.1.15",
    "10.0.1.101"
}

INTERFACE = "any"
WINDOW_SEC = 5

PPS_THRESHOLD = 1000
DOMINANCE_THRESHOLD = 0.4
ENTROPY_THRESHOLD = 0.7

RYU_URL = "http://127.0.0.1:8080/ddos_alert"

# ---------------------------------------- #

def entropy(counts):
    total = sum(counts)
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counts:
        p = c / total
        ent -= p * math.log2(p)
    return ent

# ---------------------------------------- #

def send_alert(ip, stats):
    payload = {
        "src_ip": ip,      # <-- MUST match Ryu controller
        "stats": stats     # optional, safe to keep
    }
    try:
        requests.post(RYU_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"[ERR] Failed to send alert: {e}", flush=True)


# ---------------------------------------- #

def main():
    print("[+] DDoS Monitor started")
    print(f"[+] Monitoring IPs: {', '.join(sorted(ICU_IPS))}")
    print(f"[+] Interface: {INTERFACE}")
    print(f"[+] Alerts → RYU: {RYU_URL}\n")

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        bpf_filter="ip"
    )

    window_start = time.time()
    ip_packets = defaultdict(int)
    total_packets = 0

    for pkt in capture.sniff_continuously():
        now = time.time()

        try:
            src = pkt.ip.src
        except Exception:
            continue

        if src not in ICU_IPS:
            continue

        ip_packets[src] += 1
        total_packets += 1

        if now - window_start >= WINDOW_SEC:
            if total_packets > 0:
                shares = {ip: c / total_packets for ip, c in ip_packets.items()}
                dominant_ip, dominant_share = max(shares.items(), key=lambda x: x[1])

                ent = entropy(ip_packets.values())
                pps = total_packets / WINDOW_SEC

                print(
                    f"[ICU-WINDOW] pkts={total_packets} "
                    f"pps={pps:.1f} "
                    f"entropy={ent:.3f} "
                    f"dom={dominant_ip}({dominant_share:.2f})",
                    flush=True
                )

                for ip, count in sorted(ip_packets.items(), key=lambda x: x[1], reverse=True):
                    print(
                        f"  └─ ICU {ip}: pkts={count} share={count/total_packets:.2f}",
                        flush=True
                    )

                if (
                    pps >= PPS_THRESHOLD
                    or dominant_share >= DOMINANCE_THRESHOLD
                    or ent <= ENTROPY_THRESHOLD
                ):
                    print(f"[ALERT] Suspected DDoS from {dominant_ip}", flush=True)
                    send_alert(dominant_ip, {
                        "pps": pps,
                        "entropy": ent,
                        "share": dominant_share
                    })

            # reset window
            window_start = now
            ip_packets.clear()
            total_packets = 0

# ---------------------------------------- #

if __name__ == "__main__":
    main()

