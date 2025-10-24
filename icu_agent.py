#!/usr/bin/env python3
"""
icu_agent.py
Sends JSON POSTs to hospital endpoint /ingest.
Also logs per-ICU CPU, NIC stats, TCP retransmissions, plus loss and jitter estimates.
Loss is measured as failed POSTs (timeouts/exceptions) / total sends.
Jitter uses an RTP-style running estimator:
    J += (|D| - J) / 16
where D is difference between consecutive RTTs (transit times).

ADDED: per-send tcp retransmission delta tracking by sampling /proc/net/snmp
immediately before and after the HTTP POST. The new CSV column is:
  tcp_retrans_delta
"""
import argparse, json, time, random, urllib.request, uuid, csv, psutil, re, os, socket

# --- utils ---
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def gen_vitals():
    hr = random.gauss(80, 10)
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
    """Return (success_bool, response_text_or_error, rtt_seconds_or_none)."""
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(endpoint, data=data, headers={'Content-Type': 'application/json'})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            rtt = time.time() - t0
            return True, body, rtt
    except Exception as e:
        # classify common timeout/connection errors similarly
        return False, f"ERR: {e}", None

def read_tcp_retrans():
    """
    Read /proc/net/snmp and return the cumulative RetransSegs value (int).
    Returns None on error.
    """
    try:
        with open('/proc/net/snmp','r') as f:
            lines = f.readlines()
        tcp_line, tcp_vals = None, None
        for i in range(len(lines)):
            if lines[i].startswith('Tcp:') and i+1 < len(lines):
                tcp_line = lines[i].strip().split()
                tcp_vals = lines[i+1].strip().split()
                if tcp_line[0] == 'Tcp:':
                    break
        if tcp_line and tcp_vals:
            tcp_dict = dict(zip(tcp_line[1:], map(int, tcp_vals[1:])))
            return tcp_dict.get('RetransSegs', 0)
    except Exception:
        return None

def collect_metrics():
    metrics = {}
    metrics['cpu_percent'] = psutil.cpu_percent(interval=None)
    # NIC stats (eth0)
    try:
        with open('/proc/net/dev','r') as f:
            lines = f.readlines()
        for line in lines[2:]:
            if 'eth0' in line:
                parts = re.split(r'[:\s]+', line.strip())
                metrics['rx_bytes'] = int(parts[1])
                metrics['rx_drop']  = int(parts[4])
                metrics['tx_bytes'] = int(parts[9])
                metrics['tx_drop']  = int(parts[12])
                break
    except Exception as e:
        metrics['nic_err'] = str(e)
    # TCP retransmissions (cumulative)
    try:
        trs = read_tcp_retrans()
        metrics['tcp_retrans_segs'] = trs if trs is not None else 0
    except Exception as e:
        metrics['tcp_err'] = str(e)
    return metrics

# --- main loop ---
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', required=True)
    p.add_argument('--port', type=int, default=8000)
    p.add_argument('--id', default=str(uuid.uuid4())[:8])
    p.add_argument('--interval', type=float, default=2.0)
    p.add_argument('--timeout', type=float, default=5.0, help="HTTP request timeout (s)")
    args = p.parse_args()

    endpoint = f"http://{args.host}:{args.port}/ingest"
    log(f"[ICU {args.id}] sending to {endpoint} every {args.interval}s")

    csv_file = f"{args.id}_metrics.csv"
    if not os.path.isfile(csv_file):
        with open(csv_file,'w',newline='') as f:
            writer = csv.writer(f)
            # Added tcp_retrans_delta column
            writer.writerow([
                'timestamp','seq','cpu_percent','rx_bytes','tx_bytes','rx_drop','tx_drop',
                'tcp_retrans_segs','tcp_retrans_delta','send_success','rtt_ms','jitter_ms',
                'total_sent','total_success','total_failures','loss_rate'
            ])

    # running counters & jitter state
    total_sent = 0
    total_success = 0
    total_failures = 0
    prev_transit = None   # previous RTT (seconds)
    jitter = 0.0          # smoothed jitter in seconds (RFC-style)

    counter = 0
    while True:
        vitals = gen_vitals()
        payload = {
            "icu_id": args.id,
            "seq": counter,
            "timestamp": time.time(),
            "vitals": vitals
        }

        # Sample cumulative retransmits BEFORE sending
        retrans_before = read_tcp_retrans()
        if retrans_before is None:
            retrans_before = 0

        total_sent += 1
        success, resp_text, rtt = post(endpoint, payload, timeout=args.timeout)

        # Sample cumulative retransmits AFTER sending
        retrans_after = read_tcp_retrans()
        if retrans_after is None:
            retrans_after = retrans_before  # avoid negative/None
        tcp_retrans_delta = max(0, retrans_after - retrans_before)

        if success:
            total_success += 1
            transit = rtt  # RTT in seconds
            # update jitter using RFC-style estimator: J += (|D| - J)/16
            if prev_transit is not None:
                D = abs(transit - prev_transit)
                jitter += (D - jitter) / 16.0
            prev_transit = transit
            rtt_ms = round(transit * 1000.0, 3)
        else:
            total_failures += 1
            rtt_ms = None
            # we don't update transit/jitter on failed sends

        loss_rate = total_failures / total_sent if total_sent > 0 else 0.0
        jitter_ms = round(jitter * 1000.0, 3)

        metrics = collect_metrics()

        # write CSV row (include retrans delta)
        with open(csv_file,'a',newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                time.time(),
                counter,
                metrics.get('cpu_percent',0),
                metrics.get('rx_bytes',0),
                metrics.get('tx_bytes',0),
                metrics.get('rx_drop',0),
                metrics.get('tx_drop',0),
                metrics.get('tcp_retrans_segs',0),
                tcp_retrans_delta,
                1 if success else 0,
                rtt_ms if rtt_ms is not None else '',
                jitter_ms,
                total_sent,
                total_success,
                total_failures,
                round(loss_rate,6)
            ])

        log_msg = f"[ICU {args.id}] seq={counter} sent_success={1 if success else 0} loss_rate={loss_rate:.3f} jitter={jitter_ms}ms retrans_delta={tcp_retrans_delta}"
        if rtt_ms is not None:
            log_msg += f" rtt={rtt_ms}ms"
        else:
            log_msg += f" rtt=ERR"
        log(log_msg)

        counter += 1
        time.sleep(args.interval)

if __name__ == '__main__':
    main()
