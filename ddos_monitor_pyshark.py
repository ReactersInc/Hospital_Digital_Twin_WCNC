#!/usr/bin/env python3
"""
Lightweight DDoS detector using pyshark packet capture.
Detects likely attacker IP (dominant source) using Shannon entropy + bandwidth + jitter + PPS.
Tracks per-IP metrics (including jitter).
Sends alert to an aggregator endpoint (HTTP POST) when a source is flagged.
"""


import math, time, threading, statistics, requests
from collections import deque, Counter

try:
    import pyshark
except Exception as e:
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

                    if self.debug:
                        print(f"[capture:{self.interface}] src={src} len={length} ts={now:.6f}", flush=True)

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
                    print(f"[ddos_monitor:{self.interface}] window empty", flush=True)
                if callable(self.on_window):
                    window_metrics = {
                        "timestamp": time.time(),
                        "interface": self.interface,
                        "packet_count": 0,
                        "pps": 0.0,
                        "bandwidth_mbps": 0.0,
                        "jitter_ms": 0.0,
                        "entropy": 0.0,
                        "dominant_src": None,
                        "dominant_share": 0.0,
                        "ip_stats": {},
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
            self.ip_stats.clear()
            for ip, cnt in counts.items():
                ip_bytes = sum(p["length"] for p in pkts if p["src"] == ip)
                ip_pps = cnt / duration
                ip_bw_mbps = ip_bytes * 8 / duration / 1e6
                self.ip_stats[ip] = {
                    "pps": round(ip_pps, 2),
                    "bandwidth_mbps": round(ip_bw_mbps, 2),
                    "packet_count": cnt,
                }

            srcs = [ip for ip, cnt in counts.items() for _ in range(cnt)]
            entropy = float(self.shannon_entropy(srcs)) if srcs else 0.0
            dominant_src, dominant_count = counts.most_common(1)[0] if counts else (None, 0)
            dominant_share = dominant_count / pkt_count if pkt_count else 0.0

            times = [p["ts"] for p in pkts]
            inter_arrivals = [t2 - t1 for t1, t2 in zip(times, times[1:])] if len(times) >= 2 else []
            jitter_ms = float(statistics.pstdev(inter_arrivals) * 1000.0) if inter_arrivals else 0.0

            window_metrics = {
                "timestamp": time.time(),
                "interface": self.interface,
                "packet_count": pkt_count,
                "pps": round(pps, 3),
                "bandwidth_mbps": round(bandwidth_mbps, 6),
                "jitter_ms": round(jitter_ms, 6),
                "entropy": round(entropy, 6),
                "dominant_src": dominant_src,
                "dominant_share": round(dominant_share, 6),
                "ip_stats": self.ip_stats.copy(),
            }

            if callable(self.on_window):
                try:
                    self.on_window(window_metrics)
                except Exception:
                    pass

            if self.debug:
                print(
                    f"[ddos_monitor:{self.interface}] pkts={pkt_count} pps={pps:.1f} bw={bandwidth_mbps:.2f}Mbps "
                    f"jitter={jitter_ms:.2f}ms entropy={entropy:.3f} dom_src={dominant_src}({dominant_share*100:.1f}%)",
                    flush=True,
                )

            # Detect multiple suspicious IPs
            suspicious_ips = []
            for ip, cnt in counts.items():
                ip_share = cnt / pkt_count
                ip_bytes = sum(p["length"] for p in pkts if p["src"] == ip)
                ip_bw_mbps = ip_bytes * 8 / duration / 1e6
                ip_pps = cnt / duration
                if ip_share >= 0.2 or ip_bw_mbps >= 1 or ip_pps >= 50:
                    suspicious_ips.append({
                        "ip": ip,
                        "share": round(ip_share, 3),
                        "pps": round(ip_pps, 2),
                        "bandwidth_mbps": round(ip_bw_mbps, 2),
                    })

            low_entropy = entropy < self.entropy_threshold
            high_jitter = jitter_ms >= self.jitter_threshold_ms
            high_pps = pps >= self.pps_threshold
            high_bw = bandwidth_mbps >= self.bandwidth_threshold_mbps

            if suspicious_ips and (low_entropy or high_jitter or high_pps or high_bw):
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
                        import requests
                        requests.post(self.alert_url, json=alert, timeout=3)
                    except Exception:
                        if self.debug:
                            print(f"[ddos_monitor:{self.interface}] alert POST failed", flush=True)

            time.sleep(self.window_seconds)

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
        
    pass