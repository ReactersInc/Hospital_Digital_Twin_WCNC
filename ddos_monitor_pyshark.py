#!/usr/bin/env python3
# ddos_monitor_pyshark.py
"""
Lightweight DDoS detector using pyshark packet capture.
Detects likely attacker IP (dominant source) using Shannon entropy + bandwidth + jitter + PPS
Sends alert to an aggregator endpoint (HTTP POST) when a source is flagged.

Added:
 - on_alert callback: function(alert_dict) called on local process when alert triggers.
 - posts to alert_url if provided (same as before).
"""

import time
import math
import threading
import statistics
from collections import deque, Counter
import json
import requests

try:
    import pyshark
except Exception as e:
    # keep raising a clear error if pyshark/tshark missing
    raise RuntimeError("pyshark import failed. Ensure tshark is installed and pyshark is installed.") from e


class DDoSMonitor:
    def __init__(
        self,
        interface="eth0",
        window_seconds=5,
        sample_capacity=10000,
        bpf_filter="ip",
        entropy_threshold=1.0,
        dominance_share_threshold=0.6,
        bandwidth_threshold_mbps=80.0,
        jitter_threshold_ms=20.0,
        pps_threshold=1000.0,
        alert_url=None,
        alert_auth_header=None,
        on_alert=None,
        debug=False,
    ):
        """
        interface: network interface to capture on (e.g., 'eth0' or 'h1-eth0' inside Mininet host)
        on_alert: optional callback function(alert_dict) for local handling (e.g., write CSV)
        alert_url: optional HTTP endpoint to POST alerts to
        """
        self.interface = interface
        self.window_seconds = window_seconds
        self.sample_capacity = sample_capacity
        self.bpf_filter = bpf_filter
        self.entropy_threshold = float(entropy_threshold)
        self.dominance_share_threshold = float(dominance_share_threshold)
        self.bandwidth_threshold_mbps = float(bandwidth_threshold_mbps)
        self.jitter_threshold_ms = float(jitter_threshold_ms)
        self.pps_threshold = float(pps_threshold)
        self.alert_url = alert_url
        self.alert_headers = alert_auth_header or {"Content-Type": "application/json"}
        self.on_alert = on_alert
        self.debug = debug

        self.packets = deque(maxlen=self.sample_capacity)
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._agg_thread = None

    @staticmethod
    def shannon_entropy(items):
        if not items:
            return 0.0
        counts = Counter(items)
        total = sum(counts.values())
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def _prune_old(self, now_ts):
        cutoff = now_ts - self.window_seconds
        while self.packets and self.packets[0]["ts"] < cutoff:
            self.packets.popleft()

    def _capture_loop(self):
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter)
        try:
            for pkt in capture.sniff_continuously():
                if self._stop_event.is_set():
                    break
                try:
                    now = time.time()
                    length = 0
                    try:
                        length = int(pkt.length)
                    except Exception:
                        try:
                            length = int(pkt.frame_info.len)
                        except Exception:
                            length = 0

                    src = None
                    if hasattr(pkt, "ip") and hasattr(pkt.ip, "src"):
                        src = pkt.ip.src
                    elif hasattr(pkt, "ipv6") and hasattr(pkt.ipv6, "src"):
                        src = pkt.ipv6.src
                    else:
                        continue

                    self.packets.append({"ts": now, "src": src, "length": length})
                except Exception:
                    continue
        except Exception as e:
            raise RuntimeError(f"pyshark capture error on {self.interface}: {e}") from e

    def _aggregate_and_detect(self):
        while not self._stop_event.is_set():
            now = time.time()
            self._prune_old(now)
            pkts = list(self.packets)
            pkt_count = len(pkts)
            if pkt_count == 0:
                if self.debug:
                    print(f"[ddos_monitor:{self.interface}] no packets in window")
                time.sleep(self.window_seconds)
                continue

            duration = min(self.window_seconds, max(1e-6, (pkts[-1]["ts"] - pkts[0]["ts"])))
            pps = pkt_count / duration if duration > 0 else pkt_count / self.window_seconds
            total_bytes = sum(p["length"] for p in pkts)
            bandwidth_mbps = (total_bytes * 8) / max(self.window_seconds, duration) / 1e6

            srcs = [p["src"] for p in pkts if p["src"]]
            entropy = float(self.shannon_entropy(srcs))
            counts = Counter(srcs)
            dominant_src, dominant_count = counts.most_common(1)[0]
            dominant_share = dominant_count / pkt_count

            times = [p["ts"] for p in pkts]
            inter_arrivals = [t2 - t1 for t1, t2 in zip(times, times[1:])] if len(times) >= 2 else []
            jitter_ms = float(statistics.pstdev(inter_arrivals) * 1000.0) if inter_arrivals else 0.0

            if self.debug:
                print(
                    f"[ddos_monitor:{self.interface}] window={self.window_seconds}s pkts={pkt_count} pps={pps:.1f} "
                    f"bw={bandwidth_mbps:.2f}Mbps jitter={jitter_ms:.2f}ms entropy={entropy:.3f} "
                    f"dom_src={dominant_src}({dominant_share*100:.1f}%)"
                )

            low_entropy = entropy < self.entropy_threshold
            high_dominance = dominant_share >= self.dominance_share_threshold
            high_bw = bandwidth_mbps >= self.bandwidth_threshold_mbps
            high_jitter = jitter_ms >= self.jitter_threshold_ms
            high_pps = pps >= self.pps_threshold

            is_suspicious = (low_entropy or high_dominance) and (high_bw or high_jitter or high_pps)

            if is_suspicious:
                alert = {
                    "detected_at": time.time(),
                    "interface": self.interface,
                    "window_seconds": self.window_seconds,
                    "packet_count": pkt_count,
                    "pps": round(pps, 3),
                    "bandwidth_mbps": round(bandwidth_mbps, 6),
                    "jitter_ms": round(jitter_ms, 6),
                    "entropy": round(entropy, 6),
                    "dominant_src": dominant_src,
                    "dominant_share": round(dominant_share, 6),
                    "reason": {
                        "low_entropy": low_entropy,
                        "high_dominance": high_dominance,
                        "high_bw": high_bw,
                        "high_jitter": high_jitter,
                        "high_pps": high_pps,
                    },
                }
                self._handle_alert(alert)

            time.sleep(self.window_seconds)

    def _handle_alert(self, alert):
        # local callback first
        try:
            if callable(self.on_alert):
                try:
                    self.on_alert(alert)
                except Exception as e:
                    if self.debug:
                        print(f"[ddos_monitor:{self.interface}] on_alert callback error: {e}")
        except Exception:
            pass

        # post to aggregator endpoint if configured
        if self.alert_url:
            try:
                r = requests.post(self.alert_url, headers=self.alert_headers, json=alert, timeout=3)
                if self.debug:
                    if 200 <= r.status_code < 300:
                        print(f"[ddos_monitor:{self.interface}] alert delivered to {self.alert_url} => {r.status_code}")
                    else:
                        print(f"[ddos_monitor:{self.interface}] alert POST failed {r.status_code}: {r.text}")
            except Exception as e:
                print(f"[ddos_monitor:{self.interface}] failed to POST alert to {self.alert_url}: {e}")

    def start(self, background=True):
        if self._capture_thread and self._capture_thread.is_alive():
            return

        self._stop_event.clear()
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        self._agg_thread = threading.Thread(target=self._aggregate_and_detect, daemon=True)
        self._agg_thread.start()

        if not background:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        self._stop_event.set()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
