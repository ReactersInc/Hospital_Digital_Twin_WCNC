#!/usr/bin/env python3
"""
aggregator_server.py
Usage: python3 aggregator_server.py --port 9000
Receives POSTs at /summary and logs them.
"""
import http.server, socketserver, json, time

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
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode())
        except Exception as e:
            self._set_resp(400)
            self.wfile.write(b'{"error":"bad json"}')
            return
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('timestamp', time.time())))
        print(f"[Aggregator] summary received at {ts} n_records={data.get('n_records')}")
        # Optional: pretty print per_vital
        for k, v in (data.get('per_vital') or {}).items():
            print(f"  {k}: mean={v['mean']} std={v['std']} count={v['count']} risk={v['partial_risk']}")
        self._set_resp(200)
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        return

def run(port):
    server = socketserver.ThreadingTCPServer(('0.0.0.0', port), AggHandler)
    server.daemon_threads = True
    print(f"[Aggregator] listening on {port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("aggregator shutting down")

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=9000)
    args = p.parse_args()
    run(args.port)
