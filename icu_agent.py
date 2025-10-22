#!/usr/bin/env python3
"""
icu_agent.py
Usage: python3 icu_agent.py --host 10.0.0.X --port 8000 --id icu1 --interval 2
Sends JSON POSTs to hospital endpoint /ingest.
"""
import argparse, json, time, random, urllib.request, urllib.error, urllib.parse, uuid

def log(msg):
    """Print timestamped log, flushed immediately for Mininet."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def gen_vitals():
    # realistic-ish ranges
    hr = random.gauss(80, 10)            # heart rate
    spo2 = min(100, max(80, random.gauss(97, 1.5)))
    sys_bp = random.gauss(120, 12)
    dia_bp = random.gauss(78, 8)
    rr = random.gauss(16, 2)
    temp = random.gauss(37, 0.4)
    return {
        "heart_rate": round(hr,1),
        "spo2": round(spo2,1),
        "systolic_bp": round(sys_bp,1),
        "diastolic_bp": round(dia_bp,1),
        "resp_rate": round(rr,1),
        "temperature": round(temp,2)
    }

def post(endpoint, payload, timeout=5):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(endpoint, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode()
    except Exception as e:
        return f"ERR: {e}"

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=8000)
    p.add_argument('--id', default=str(uuid.uuid4())[:8])
    p.add_argument('--interval', type=float, default=2.0)
    args = p.parse_args()

    endpoint = f"http://{args.host}:{args.port}/ingest"
    log(f"[ICU {args.id}] sending to {endpoint} every {args.interval}s")
    counter = 0
    while True:
        vitals = gen_vitals()
        payload = {
            "icu_id": args.id,
            "seq": counter,
            "timestamp": time.time(),
            "vitals": vitals
        }
        resp = post(endpoint, payload)
        log(f"[ICU {args.id}] sent seq={counter} resp={resp}")
        counter += 1
        time.sleep(args.interval)

if __name__ == '__main__':
    main()
