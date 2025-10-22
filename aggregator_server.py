#!/usr/bin/env python3
"""
aggregator_server.py (instrumented)

- Accepts /summary posts from hospitals
- Collects per-global-round summaries from expected clients (or times out)
- Computes round metrics and appends to CSV (rounds_summary.csv)
- Timestamped logging with flush
"""
import http.server, socketserver, json, time, threading, argparse, os, csv, statistics

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

class AggHandler(http.server.BaseHTTPRequestHandler):
    def _set_resp(self, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        if self.path != '/summary':
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
        except Exception:
            self._set_resp(400)
            self.wfile.write(b'{"error":"bad json"}')
            return
        data['_arrived_at'] = time.time()
        # include remote host as identifier if present
        source = self.client_address[0]
        data['_source_ip'] = source
        # enqueue into server collector
        self.server.enqueue_summary(data)
        self._set_resp(200)
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        return

class AggregatorServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    def __init__(self, addr, handler, expected_clients=3, round_timeout=5.0, csvfile='rounds_summary.csv'):
        super().__init__(addr, handler)
        self.lock = threading.Lock()
        self.current_round = 1
        self.expected_clients = expected_clients
        self.round_timeout = float(round_timeout)
        # buffer for current round: list of dict summaries
        self.round_buffer = []
        self.round_start = time.time()
        self.csvfile = csvfile
        # ensure CSV exists with header
        if not os.path.exists(self.csvfile):
            with open(self.csvfile, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['global_round','started_at','finished_at','round_time','n_expected','n_received','avg_local_train_time','avg_model_delta_norm','avg_staleness','hosts'])
        # start round monitor thread
        t = threading.Thread(target=self._round_monitor_loop, daemon=True)
        t.start()

    def enqueue_summary(self, summary):
        with self.lock:
            # attach the server-received global round snapshot
            summary['_received_for_round'] = self.current_round
            self.round_buffer.append(summary)
            log(f"[Aggregator] summary received from {summary.get('_source_ip')} for round_snapshot={self.current_round} local_round={summary.get('local_round')} delta_norm={summary.get('model_delta_norm')}")
            # if we have expected clients, close round immediately
            if len(self.round_buffer) >= self.expected_clients:
                log("[Aggregator] expected clients reached, closing round early.")
                self._close_round()

    def _round_monitor_loop(self):
        while True:
            try:
                with self.lock:
                    elapsed = time.time() - self.round_start
                    if elapsed >= self.round_timeout and self.round_buffer:
                        log(f"[Aggregator] round_timeout reached ({elapsed:.1f}s), closing round.")
                        self._close_round()
                time.sleep(0.5)
            except Exception as e:
                log(f"[Aggregator] round monitor ERR: {e}")
                time.sleep(1.0)

    def _close_round(self):
        # snapshot and reset for next round
        buffer = list(self.round_buffer)
        started_at = self.round_start
        finished_at = time.time()
        self.round_buffer.clear()
        self.round_start = time.time()
        global_round = self.current_round
        self.current_round += 1

        n_received = len(buffer)
        n_expected = self.expected_clients

        # compute metrics
        local_train_times = [s.get('local_train_time', 0.0) for s in buffer]
        delta_norms = [s.get('model_delta_norm', 0.0) for s in buffer]
        stalenesses = []
        for s in buffer:
            local_round = s.get('local_round', None)
            if local_round is None:
                # absent local_round -> treat as 0 staleness (or mark as unknown)
                stalenesses.append(0.0)
            else:
                stalenesses.append(max(0, global_round - local_round))

        avg_train = round(statistics.mean(local_train_times),6) if local_train_times else 0.0
        avg_delta = round(statistics.mean(delta_norms),6) if delta_norms else 0.0
        avg_stal = round(statistics.mean(stalenesses),6) if stalenesses else 0.0

        round_time = finished_at - started_at

        # write CSV row
        row = [global_round, started_at, finished_at, round_time, n_expected, n_received, avg_train, avg_delta, avg_stal, ','.join([s.get('_source_ip','?') for s in buffer])]
        try:
            with open(self.csvfile, 'a', newline='') as f:
                w = csv.writer(f)
                w.writerow(row)
            log(f"[Aggregator] closed round={global_round} recv={n_received}/{n_expected} round_time={round_time:.3f}s avg_train={avg_train} avg_delta={avg_delta} avg_staleness={avg_stal}")
        except Exception as e:
            log(f"[Aggregator] CSV write ERR: {e}")

def run(port, expected_clients=3, round_timeout=5.0, csvfile='rounds_summary.csv'):
    server = AggregatorServer(('0.0.0.0', port), AggHandler, expected_clients=int(expected_clients), round_timeout=float(round_timeout), csvfile=csvfile)
    log(f"[Aggregator] listening on {port} expected_clients={expected_clients} round_timeout={round_timeout}s csv={csvfile}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Aggregator shutting down")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--expected_clients', type=int, default=3)
    parser.add_argument('--round_timeout', type=float, default=5.0)
    parser.add_argument('--csv', default='rounds_summary.csv')
    args = parser.parse_args()
    run(args.port, args.expected_clients, args.round_timeout, args.csv)
