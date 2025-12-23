#!/usr/bin/env python3
"""
Mininet Healthcare Topology with
CSCS-based Critical Node Identification
(DDoS-focused, paper-faithful implementation)
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

import time
import threading
import networkx as nx
import numpy as np
from statistics import mean, stdev

# ================= CONFIG ================= #
ICU_SCRIPT = "icu_agent.py"
HOSPITAL_SCRIPT = "hospital_server.py"
AGG_SCRIPT = "aggregator_server.py"

ICUS_PER_HOSP = 3
HOSP_COUNT = 2

HOSP_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3."]
HOSP_PORTS = [8001, 8002, 8003]

# ========================================= #
# ============== TOPOLOGY ================== #
# ========================================= #

class HospitalTopo(Topo):
    def build(self):
        main = self.addSwitch('s1')

        agg = self.addHost('agg', ip='10.0.0.10/24', cpu=.1)
        agg_sw = self.addSwitch('s2')
        self.addLink(agg, agg_sw)
        self.addLink(agg_sw, main, bw=1000)

        attacker = self.addHost('attacker', ip='10.0.0.99/24', cpu=.5)
        self.addLink(attacker, main, bw=1000)

        for i in range(HOSP_COUNT):
            hs = self.addSwitch(f's{3+i}')
            self.addLink(hs, main, bw=5)

            subnet = HOSP_SUBNETS[i]
            hosp = self.addHost(f'h{i+1}', ip=f'{subnet}1/24', cpu=.05)
            self.addLink(hosp, hs, bw=5)

            for j in range(ICUS_PER_HOSP):
                icu = self.addHost(
                    f'h{i+1}icu{j+1}',
                    ip=f'{subnet}{11+j}/24',
                    cpu=.02
                )
                self.addLink(icu, hs, bw=1, delay='10ms')

            hatt = self.addHost(
                f'h{i+1}att',
                ip=f'{subnet}101/24',
                cpu=.3
            )
            self.addLink(hatt, hs, bw=1000)

# ========================================= #
# ========== CSCS IMPLEMENTATION =========== #
# ========================================= #

class NodeState:
    def __init__(self, node_id):
        self.node_id = node_id
        self.vulnerability = 0.0
        self.traffic = 0.0
        self.load_variation = 0.0
        self.temporal_change = 0.0

def build_graph():
    G = nx.Graph()
    G.add_node("agg")

    for h in range(1, HOSP_COUNT + 1):
        hosp = f"h{h}"
        G.add_edge("agg", hosp)

        for i in range(1, ICUS_PER_HOSP + 1):
            G.add_edge(hosp, f"h{h}icu{i}")

        G.add_edge(hosp, f"h{h}att")

    G.add_edge("agg", "attacker")
    return G

def compute_centrality(G):
    deg = nx.degree_centrality(G)
    bet = nx.betweenness_centrality(G)
    clo = nx.closeness_centrality(G)
    eig = nx.eigenvector_centrality(G, max_iter=500)

    return {
        k: 0.25 * deg[k] + 0.25 * bet[k] + 0.25 * clo[k] + 0.25 * eig[k]
        for k in G.nodes()
    }

def compute_security_metric(G, states):
    S = {}
    for k in G.nodes():
        score = 0.6 * states[k].vulnerability

        for j in G.neighbors(k):
            score += 0.3 * states[j].vulnerability

        for j in G.neighbors(k):
            for m in G.neighbors(j):
                if m != k:
                    score += 0.1 * states[m].vulnerability

        S[k] = score
    return S

def compute_dynamic_factor(states):
    return {
        k: 0.4 * s.traffic + 0.3 * s.load_variation + 0.3 * s.temporal_change
        for k, s in states.items()
    }

def compute_cscs(C, S, D):
    return {
        k: 0.4 * C[k] + 0.35 * S[k] + 0.25 * D[k]
        for k in C
    }

def detect_critical_nodes(CSCS, r=1.2):
    values = list(CSCS.values())
    mu = mean(values)
    sigma = stdev(values) if len(values) > 1 else 0.0
    tau = mu + r * sigma

    return {k: v for k, v in CSCS.items() if v >= tau}, tau

# ========================================= #
# ============ RUNTIME MONITOR ============= #
# ========================================= #

def update_metrics(states):
    for k in states:
        states[k].traffic = np.random.rand() * 0.3
        states[k].load_variation = np.random.rand() * 0.2
        states[k].temporal_change = np.random.rand() * 0.1
        states[k].vulnerability = 0.1

    # Simulated DDoS
    states["h1att"].traffic = 1.0
    states["h1att"].vulnerability = 0.9
    states["h1"].traffic = 0.9
    states["h1"].load_variation = 0.8
    states["h1"].vulnerability = 0.6

def cscs_monitor():
    G = build_graph()
    states = {k: NodeState(k) for k in G.nodes()}

    while True:
        update_metrics(states)

        C = compute_centrality(G)
        S = compute_security_metric(G, states)
        D = compute_dynamic_factor(states)
        CSCS = compute_cscs(C, S, D)

        critical, tau = detect_critical_nodes(CSCS)

        print("\n================ CSCS MONITOR ================")
        print(f"Threshold τ = {tau:.4f}")
        for k, v in critical.items():
            print(f"⚠ CRITICAL NODE: {k} | CSCS={v:.4f}")
        print("=============================================")

        time.sleep(5)

# ========================================= #
# ============ SERVICE STARTUP ============== #
# ========================================= #

def start_services(net):
    agg = net.get('agg')
    agg.cmd(f'python3 -u {AGG_SCRIPT} --port 9000 > agg.log 2>&1 &')
    time.sleep(0.3)

    for i in range(HOSP_COUNT):
        hosp = net.get(f'h{i+1}')
        port = HOSP_PORTS[i]
        iface = f'{hosp.name}-eth0'
        cmd = (
            f'python3 -u {HOSPITAL_SCRIPT} '
            f'--port {port} --agg_host 10.0.0.10 '
            f'--agg_port 9000 --iface {iface} '
            f'--name {hosp.name} > {hosp.name}.log 2>&1 &'
        )
        hosp.cmd(cmd)
        time.sleep(0.2)

    for i in range(HOSP_COUNT):
        hosp_ip = net.get(f'h{i+1}').IP()
        port = HOSP_PORTS[i]
        for j in range(ICUS_PER_HOSP):
            icu = net.get(f'h{i+1}icu{j+1}')
            icu.cmd(
                f'python3 -u {ICU_SCRIPT} '
                f'--host {hosp_ip} --port {port} '
                f'--id {icu.name} > {icu.name}.log 2>&1 &'
            )

# ========================================= #
# ================= MAIN =================== #
# ========================================= #

def main():
    setLogLevel('info')
    topo = HospitalTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    net.start()
    print("\n✅ Network started")

    start_services(net)

    # Start CSCS monitor thread
    threading.Thread(target=cscs_monitor, daemon=True).start()

    CLI(net)

    print("[cleanup] stopping services...")
    for h in net.hosts:
        h.cmd(f'pkill -f {ICU_SCRIPT} || true')
        h.cmd(f'pkill -f {HOSPITAL_SCRIPT} || true')
        h.cmd(f'pkill -f {AGG_SCRIPT} || true')

    net.stop()
    print("✅ Network stopped")

if __name__ == "__main__":
    main()
