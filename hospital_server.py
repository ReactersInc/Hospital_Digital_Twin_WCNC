#!/usr/bin/env python3
"""
hospital_server.py
Enhanced with timestamped logs for Mininet usage.
"""
import argparse, json, time, threading, urllib.request, urllib.parse, http.server, socketserver, math
from collections import defaultdict, deque

def log(msg):
    """Print timestamped log, flushed immediately for Mininet."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

class HospitalHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HospitalHTTP/0.1"

    def _set_resp(self, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path != '/ingest':
            self._set_resp(404)
            self.wfile.write(b'{"error":"not found"}')
            return
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            self._set_resp(400)
            self.wfile.write(b'{"error":"no body"}')
            return
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode())
        except Exception as e:
            self._set_resp(400)
            self.wfile.write(b'{"error":"bad json"}')
            return
        self.server.enqueue(data)
        self._set_resp(200)
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        # silence default HTTP logs
        return

class HospitalServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, batch, forward_url):
        super().__init__(server_address, RequestHandlerClass)
        self.queue = deque()
        self.lock = threading.Lock()
        self.batch = batch
        self.forward_url = forward_url
        self.stats = defaultdict(lambda: {"count":0, "mean":0.0, "M2":0.0})

    def enqueue(self, data):
        with self.lock:
            self.queue.append(data)

    def process_loop(self):
        while True:
            self._maybe_process()
            time.sleep(0.5)

    def _maybe_process(self):
        items = []
        with self.lock:
            while self.queue and len(items) < self.batch:
                items.append(self.queue.popleft())
        if not items:
            return
        for item in items:
            vitals = item.get('vitals', {})
            for k, v in vitals.items():
                s = self.stats[k]
                s['count'] += 1
                delta = v - s['mean']
                s['mean'] += delta / s['count']
                delta2 = v - s['mean']
                s['M2'] += delta * delta2
        summary = {
            "timestamp": time.time(),
            "n_records": sum(self.stats[k]['count'] for k in self.stats),
            "per_vital": {}
        }
        for k, s in self.stats.items():
            count = s['count']
            mean = s['mean']
            variance = (s['M2'] / (count - 1)) if count > 1 else 0.0
            stddev = math.sqrt(variance) if variance > 0 else 0.0
            risk = 0.0
            if k == 'heart_rate' and mean > 110:
                risk += 0.7
            if k == 'spo2' and mean < 92:
                risk += 0.9
            risk += min(1.0, abs(mean)/200.0)
            summary['per_vital'][k] = {"count": count, "mean": round(mean,3), "std": round(stddev,3), "partial_risk": round(risk,3)}
        self._forward_summary(summary)

    def _forward_summary(self, summary):
        body = json.dumps(summary).encode('utf-8')
        req = urllib.request.Request(self.forward_url, data=body, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read().decode()
                log(f"[Hospital] forwarded summary n_records={summary['n_records']} resp={resp_body}")
        except Exception as e:
            log(f"[Hospital] forward ERR: {e}")

def run_server(port, batch, agg_host, agg_port):
    forward_url = f"http://{agg_host}:{agg_port}/summary"
    server = HospitalServer(('0.0.0.0', port), HospitalHandler, batch=batch, forward_url=forward_url)
    log(f"[Hospital] listening on {port}, forwarding summaries to {forward_url}, batch={batch}")
    t = threading.Thread(target=server.process_loop, daemon=True)
    t.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Hospital shutting down")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--agg_host', required=True)
    parser.add_argument('--agg_port', type=int, default=9000)
    parser.add_argument('--batch', type=int, default=10)
    args = parser.parse_args()
    run_server(args.port, args.batch, args.agg_host, args.agg_port)
