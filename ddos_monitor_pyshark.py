#!/usr/bin/env python3
"""
Lightweight DDoS detector using pyshark packet capture.

Detects likely attacker IPs using Shannon entropy (normalized), bandwidth, per-IP jitter, and PPS.
Tracks per-IP metrics (including smoothed jitter).
Sends alert to an aggregator endpoint (HTTP POST) when sources are flagged.
"""

import math
import time
import threading
import requests
from collections import deque, Counter

try:
    import pyshark
except Exception as e:
    raise RuntimeError("pyshark import failed. Ensure tshark and pyshark are installed.") from e


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
        jitter_threshold_ms=40.0,
        pps_threshold=1000.0,
        alert_url=None,
        on_alert=None,
        on_window=None,
        debug=False,
    ):
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
        self.on_alert = on_alert
        self.on_window = on_window
        self.debug = debug

        self.packets = deque(maxlen=self.sample_capacity)
        self.ip_stats = {}
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._agg_thread = None
        self._prev_global_jitter = 0.0

        # store previous smoothed per-ip jitter across windows
        self._prev_ip_jitter = {}

    # -------------------------------
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

    # -------------------------------
    def _prune_old(self, now_ts):
        cutoff = now_ts - self.window_seconds
        while self.packets and self.packets[0]["ts"] < cutoff:
            self.packets.popleft()

    # -------------------------------
    def _capture_loop(self):
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter)
        try:
            for pkt in capture.sniff_continuously():
                if self._stop_event.is_set():
                    break
                try:
                    now = time.time()
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

                    if self.debug:
                        print(f"[capture:{self.interface}] src={src} len={length} ts={now:.6f}", flush=True)
                except Exception:
                    continue
        except Exception as e:
            raise RuntimeError(f"pyshark capture error on {self.interface}: {e}") from e

    # -------------------------------
    @staticmethod
    def compute_jitter(times, prev_smoothed=None, alpha=0.3):
        """
        Compute mean absolute deviation (MAD) of inter-arrival times in ms,
        optionally apply exponential smoothing with previous value.
        """
        if len(times) < 2:
            return 0.0
        inter_times = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
        mean_inter = sum(inter_times) / len(inter_times)
        mad = sum(abs(x - mean_inter) for x in inter_times) / len(inter_times)
        jitter_ms = mad * 1000.0
        if prev_smoothed is not None:
            jitter_ms = alpha * jitter_ms + (1 - alpha) * prev_smoothed
        return jitter_ms

    # -------------------------------
    def _aggregate_and_detect(self):
        while not self._stop_event.is_set():
            now = time.time()
            self._prune_old(now)
            pkts = list(self.packets)
            pkt_count = len(pkts)

            if pkt_count == 0:
                if callable(self.on_window):
                    window_metrics = {
                        "timestamp": now,
                        "interface": self.interface,
                        "packet_count": 0,
                        "pps": 0.0,
                        "bandwidth_mbps": 0.0,
                        "jitter_ms": 0.0,
                        "entropy": 0.0,
                        "dominant_src": None,
                        "dominant_share": 0.0,
                        "ip_stats": {},
                        "ip_counts": {},
                        "ip_shares": {},
                    }
                    try:
                        self.on_window(window_metrics)
                    except Exception:
                        pass
                time.sleep(self.window_seconds)
                continue

            duration = max(1e-6, pkts[-1]["ts"] - pkts[0]["ts"])
            pps = pkt_count / duration
            total_bytes = sum(p["length"] for p in pkts)
            bandwidth_mbps = total_bytes * 8 / duration / 1e6
            counts = Counter(p["src"] for p in pkts if p["src"])

            # --- compute per-IP metrics ---
            ip_stats_local = {}
            ip_counts = {}
            for ip, cnt in counts.items():
                ip_times = [p["ts"] for p in pkts if p["src"] == ip]
                ip_bytes = sum(p["length"] for p in pkts if p["src"] == ip)
                ip_pps = cnt / duration
                ip_bw_mbps = ip_bytes * 8 / duration / 1e6

                prev_ip_jitter = self._prev_ip_jitter.get(ip, 0.0)
                ip_jitter_ms = self.compute_jitter(ip_times, prev_smoothed=prev_ip_jitter, alpha=0.3)

                # store smoothed jitter for next window
                self._prev_ip_jitter[ip] = ip_jitter_ms

                ip_stats_local[ip] = {
                    "pps": round(ip_pps, 2),
                    "bandwidth_mbps": round(ip_bw_mbps, 2),
                    "packet_count": cnt,
                    "jitter_ms": round(ip_jitter_ms, 3),
                }
                ip_counts[ip] = cnt

            self.ip_stats = ip_stats_local

            # --- compute global normalized entropy and dominant src ---
            srcs = [ip for ip, cnt in counts.items() for _ in range(cnt)]
            entropy_raw = float(self.shannon_entropy(srcs)) if srcs else 0.0
            unique_ips = len(counts)
            entropy_norm = entropy_raw / math.log2(unique_ips) if unique_ips > 1 else 0.0

            dominant_src, dominant_count = counts.most_common(1)[0] if counts else (None, 0)
            dominant_share = dominant_count / pkt_count if pkt_count else 0.0

            # --- global jitter (smoothed mean of per-IP jitter) ---
            if self.ip_stats:
                raw_global_jitter = sum(v["jitter_ms"] for v in self.ip_stats.values()) / len(self.ip_stats)
            else:
                raw_global_jitter = 0.0
            jitter_ms = 0.3 * raw_global_jitter + 0.7 * self._prev_global_jitter
            self._prev_global_jitter = jitter_ms

            # --- prepare ip_shares ---
            total_packets = sum(ip_counts.values()) if ip_counts else 0
            ip_shares = {ip: round(cnt / total_packets, 3) for ip, cnt in ip_counts.items()} if total_packets else {}

            # --- assemble metrics for current window ---
            window_metrics = {
                "timestamp": now,
                "interface": self.interface,
                "packet_count": pkt_count,
                "pps": round(pps, 3),
                "bandwidth_mbps": round(bandwidth_mbps, 6),
                "jitter_ms": round(jitter_ms, 6),
                "entropy": round(entropy_norm, 6),  # <--- normalized entropy
                "dominant_src": dominant_src,
                "dominant_share": round(dominant_share, 6),
                "ip_stats": self.ip_stats.copy(),
                "ip_counts": ip_counts,
                "ip_shares": ip_shares,
            }

            # --- callback for per-window data ---
            if callable(self.on_window):
                try:
                    self.on_window(window_metrics)
                except Exception:
                    pass

            if self.debug:
                print(
                    f"[ddos_monitor:{self.interface}] pkts={pkt_count} pps={pps:.1f} "
                    f"bw={bandwidth_mbps:.2f}Mbps jitter={jitter_ms:.2f}ms "
                    f"entropy={entropy_norm:.3f} dom_src={dominant_src}({dominant_share*100:.1f}%)",
                    flush=True,
                )

            # --- detect suspicious IPs ---
            suspicious_ips = []
            for ip, stats in self.ip_stats.items():
                ip_share = (counts[ip] / pkt_count) if pkt_count else 0.0
                ip_pps = stats["pps"]
                ip_bw_mbps = stats["bandwidth_mbps"]
                ip_jitter_ms = stats["jitter_ms"]

                if (
                    ip_share >= 0.2
                    or ip_bw_mbps >= 1
                    or ip_pps >= 50
                    or ip_jitter_ms >= self.jitter_threshold_ms
                ):
                    suspicious_ips.append(
                        {
                            "ip": ip,
                            "share": round(ip_share, 3),
                            "pps": ip_pps,
                            "bandwidth_mbps": ip_bw_mbps,
                            "jitter_ms": ip_jitter_ms,
                        }
                    )

            low_entropy = entropy_norm < self.entropy_threshold
            high_pps = pps >= self.pps_threshold
            high_bw = bandwidth_mbps >= self.bandwidth_threshold_mbps
            high_jitter = jitter_ms >= self.jitter_threshold_ms

            if suspicious_ips and (low_entropy or high_pps or high_bw or high_jitter):
                alert = {
                    **window_metrics,
                    "suspicious_ips": suspicious_ips,
                    "reason": {
                        "low_entropy": low_entropy,
                        "high_jitter": high_jitter,
                        "high_pps": high_pps,
                        "high_bandwidth": high_bw,
                    },
                }

                if callable(self.on_alert):
                    try:
                        self.on_alert(alert)
                    except Exception:
                        pass

                if self.alert_url:
                    try:
                        requests.post(self.alert_url, json=alert, timeout=3)
                    except Exception:
                        if self.debug:
                            print(f"[ddos_monitor:{self.interface}] alert POST failed", flush=True)

            time.sleep(self.window_seconds)

    # -------------------------------
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

    # -------------------------------
    def stop(self):
        self._stop_event.set()


    pass
