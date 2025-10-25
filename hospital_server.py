#!/usr/bin/env python3
"""
hospital_server.py

- Ingests vitals via /ingest and processes batches (logs to csv).
- Runs embedded DDoSMonitor (pyshark) on specified interface (--iface).
- Prints live capture lines (per-packet) when debug=True.
- Writes per-window metrics to ddos_metrics_<name>.csv and alerts to ddos_alerts_<name>.csv.
"""

import argparse
import csv
import json
import math
import os
import socket
import statistics
import threading
import time
import urllib.request
from collections import defaultdict, deque, Counter

import psutil
import http.server
import socketserver
import re


from ddos_monitor_pyshark import DDoSMonitor



# ---------------- Hospital Server ---------------- #

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class HospitalHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HospitalHTTP/0.1"

    def _set_resp(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_POST(self):
        if self.path != "/ingest":
            self._set_resp(404)
            self.wfile.write(b'{"error":"not found"}')
            return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._set_resp(400)
            self.wfile.write(b'{"error":"no body"}')
            return
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode())
        except Exception:
            self._set_resp(400)
            self.wfile.write(b'{"error":"bad json"}')
            return
        data["_received_at"] = time.time()
        self.server.enqueue(data)
        self._set_resp(200)
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        return


class HospitalServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, batch, forward_url, csv_file, hospital_name):
        super().__init__(server_address, RequestHandlerClass)
        self.queue = deque()
        self.lock = threading.Lock()
        self.batch = batch
        self.forward_url = forward_url
        self.local_round = 0
        self.stats = defaultdict(lambda: {"count": 0, "mean": 0.0, "M2": 0.0})
        self.csv_file = csv_file
        self.hospital_name = hospital_name

        if not os.path.isfile(csv_file):
            with open(csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                headers = [
                    "timestamp",
                    "local_round",
                    "n_records_in_batch",
                    "local_train_time",
                    "model_delta_norm",
                    "total_records_seen",
                    "cpu_percent",
                    "rx_drop",
                    "tx_drop",
                    "rx_bytes",
                    "tx_bytes",
                    "tcp_retrans_segs",
                ]
                writer.writerow(headers)

    def enqueue(self, data):
        with self.lock:
            self.queue.append(data)

    def process_loop(self):
        while True:
            try:
                self._maybe_process()
            except Exception as e:
                log(f"[Hospital] processing ERR: {e}")
            time.sleep(0.5)

    def _collect_host_metrics(self):
        metrics = {}
        try:
            metrics["cpu_percent"] = psutil.cpu_percent(interval=None)
        except Exception:
            metrics["cpu_percent"] = 0.0
        # best-effort parse /proc/net/dev for an interface line
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                if "lo" in line:
                    continue
                # choose first non-loopback (best-effort)
                parts = re.split(r"[:\s]+", line.strip())
                if len(parts) >= 13:
                    try:
                        metrics["rx_bytes"] = int(parts[1])
                        metrics["rx_drop"] = int(parts[4])
                        metrics["tx_bytes"] = int(parts[9])
                        metrics["tx_drop"] = int(parts[12])
                    except Exception:
                        pass
                    break
        except Exception:
            pass

        try:
            with open("/proc/net/snmp", "r") as f:
                lines = f.readlines()
            tcp_line = None
            tcp_vals = None
            for i in range(len(lines)):
                if lines[i].startswith("Tcp:") and i + 1 < len(lines):
                    tcp_line = lines[i].strip().split()
                    tcp_vals = lines[i + 1].strip().split()
                    if tcp_line[0] == "Tcp:":
                        break
            if tcp_line and tcp_vals:
                tcp_dict = dict(zip(tcp_line[1:], map(int, tcp_vals[1:])))
                metrics["tcp_retrans_segs"] = tcp_dict.get("RetransSegs", 0)
        except Exception:
            pass

        return metrics

    def _maybe_process(self):
        items = []
        with self.lock:
            while self.queue and len(items) < self.batch:
                items.append(self.queue.popleft())
        if not items:
            return

        t0 = time.time()
        per_vital_acc = defaultdict(list)
        for item in items:
            vitals = item.get("vitals", {})
            for k, v in vitals.items():
                try:
                    fv = float(v)
                except Exception:
                    fv = 0.0
                per_vital_acc[k].append(fv)
                s = self.stats[k]
                s["count"] += 1
                delta = fv - s["mean"]
                s["mean"] += delta / s["count"]
                delta2 = fv - s["mean"]
                s["M2"] += delta * delta2

        simulated_compute = 0.01 * len(items)
        time.sleep(simulated_compute)
        local_train_time = time.time() - t0
        batch_means = {k: (statistics.mean(vals) if vals else 0.0) for k, vals in per_vital_acc.items()}
        vec = [v for _, v in sorted(batch_means.items())]
        delta_norm = math.sqrt(sum(x * x for x in vec)) if vec else 0.0
        self.local_round += 1
        local_round = self.local_round
        host_metrics = self._collect_host_metrics()

        # write batch CSV
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            row = [
                time.time(),
                local_round,
                len(items),
                round(local_train_time, 4),
                round(delta_norm, 6),
                sum(self.stats[k]["count"] for k in self.stats),
                host_metrics.get("cpu_percent", 0.0),
                host_metrics.get("rx_drop", 0),
                host_metrics.get("tx_drop", 0),
                host_metrics.get("rx_bytes", 0),
                host_metrics.get("tx_bytes", 0),
                host_metrics.get("tcp_retrans_segs", 0),
            ]
            writer.writerow(row)

        log(
            f"[Hospital:{self.hospital_name}] round={local_round} batch={len(items)} train_time={local_train_time:.3f}s "
            f"delta_norm={delta_norm:.6f} cpu={host_metrics.get('cpu_percent',0.0)} rx_drop={host_metrics.get('rx_drop',0)} "
            f"tx_drop={host_metrics.get('tx_drop',0)} tcp_retrans={host_metrics.get('tcp_retrans_segs',0)}"
        )

        # forward summary to aggregator (best-effort)
        self._forward_summary(
            {
                "timestamp": time.time(),
                "local_round": local_round,
                "n_records_in_batch": len(items),
                "local_train_time": round(local_train_time, 4),
                "model_delta_norm": round(delta_norm, 6),
                "per_vital_batch_means": {k: round(v, 4) for k, v in batch_means.items()},
                "total_records_seen": sum(self.stats[k]["count"] for k in self.stats),
                "hospital_name": self.hospital_name,
                "host_ip": self.server_address[0] if isinstance(self.server_address, tuple) else socket.gethostname(),
            }
        )

    def _forward_summary(self, summary):
        try:
            body = json.dumps(summary).encode("utf-8")
            req = urllib.request.Request(self.forward_url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read().decode()
                log(f"[Hospital:{self.hospital_name}] forwarded summary local_round={summary['local_round']} resp={resp_body}")
        except Exception as e:
            # aggregator may not be reachable — ignore
            log(f"[Hospital:{self.hospital_name}] forward ERR: {e}")

# ---------------- Runner ---------------- #


def run_server(port, batch, agg_host, agg_port, csv_file, iface, hospital_name, debug):
    forward_url = f"http://{agg_host}:{agg_port}/summary"
    server = HospitalServer(("0.0.0.0", port), HospitalHandler, batch, forward_url, csv_file, hospital_name)

    # DDoS metrics CSV (every window)
    ddos_metrics_csv = f"ddos_metrics_{hospital_name}.csv"
    if not os.path.isfile(ddos_metrics_csv):
        with open(ddos_metrics_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "timestamp",
                    "interface",
                    "packet_count",
                    "pps",
                    "bandwidth_mbps",
                    "jitter_ms",
                    "entropy",
                    "dominant_src",
                    "dominant_share",
                ]
            )

    # DDoS alerts CSV
    ddos_alerts_csv = f"ddos_alerts_{hospital_name}.csv"
    if not os.path.isfile(ddos_alerts_csv):
        with open(ddos_alerts_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "detected_at",
                    "interface",
                    "packet_count",
                    "pps",
                    "bandwidth_mbps",
                    "jitter_ms",
                    "entropy",
                    "dominant_src",
                    "dominant_share",
                    "reason",
                ]
            )

    # on_window callback: always called each window with metrics
    def on_window(metrics):
        # write metrics row (append)
        try:
            with open(ddos_metrics_csv, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        metrics.get("timestamp", time.time()),
                        metrics.get("interface"),
                        metrics.get("packet_count"),
                        metrics.get("pps"),
                        metrics.get("bandwidth_mbps"),
                        metrics.get("jitter_ms"),
                        metrics.get("entropy"),
                        metrics.get("dominant_src"),
                        metrics.get("dominant_share"),
                    ]
                )
        except Exception as e:
            log(f"[DDoS:{hospital_name}] failed to write metrics csv: {e}")

    # on_alert callback: called only when suspicious
    def on_alert(alert):
        log(
            f"[DDoS:{hospital_name}] ALERT -> {alert.get('dominant_src')} bw={alert.get('bandwidth_mbps')}Mbps pps={alert.get('pps')} entropy={alert.get('entropy')}"
        )
        try:
            with open(ddos_alerts_csv, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        alert.get("detected_at", time.time()),
                        alert.get("interface"),
                        alert.get("packet_count"),
                        alert.get("pps"),
                        alert.get("bandwidth_mbps"),
                        alert.get("jitter_ms"),
                        alert.get("entropy"),
                        alert.get("dominant_src"),
                        alert.get("dominant_share"),
                        json.dumps(alert.get("reason", {})),
                    ]
                )
        except Exception as e:
            log(f"[DDoS:{hospital_name}] failed to write alerts csv: {e}")

    ddos_monitor = DDoSMonitor(
        interface=iface or "eth0",
        window_seconds=5,
        bpf_filter="ip",
        entropy_threshold=1.0,
        dominance_share_threshold=0.6,
        bandwidth_threshold_mbps=80.0,
        jitter_threshold_ms=20.0,
        pps_threshold=1000.0,
        alert_url=f"http://{agg_host}:{agg_port}/ddos_alert",
        on_alert=on_alert,
        on_window=on_window,
        debug=debug,
    )

    try:
        ddos_monitor.start(background=True)
    except Exception as e:
        log(f"[DDoS:{hospital_name}] failed to start on iface={iface}: {e}")

    log(f"[Hospital:{hospital_name}] listening on {port}, batch={batch}, logging to {csv_file} (ddos -> {ddos_metrics_csv}, alerts -> {ddos_alerts_csv})")
    t = threading.Thread(target=server.process_loop, daemon=True)
    t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Hospital shutting down")
        ddos_monitor.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hospital server with integrated DDoS monitor")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--agg_host", required=True, help="aggregator host/address")
    parser.add_argument("--agg_port", type=int, default=9000)
    parser.add_argument("--batch", type=int, default=10)
    parser.add_argument("--csv_file", type=str, default="hospital_metrics.csv")
    parser.add_argument("--iface", type=str, default="eth0", help="interface for pyshark (e.g., h1-eth0 in Mininet)")
    parser.add_argument("--name", type=str, default="hospital", help="hospital name used for logs/csv")
    parser.add_argument("--debug", action="store_true", help="enable verbose pyshark + monitor logging")
    args = parser.parse_args()

    run_server(args.port, args.batch, args.agg_host, args.agg_port, args.csv_file, args.iface, args.name, args.debug)