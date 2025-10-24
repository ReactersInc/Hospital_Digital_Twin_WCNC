#!/usr/bin/env python3
"""
mininet_launch.py

Starts Mininet topology and runs aggregator and hospital/ICU scripts inside hosts.
This file was adapted to start hospital_server with `--iface` and `--name` to make DDoSMonitor accurate.
"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import time
import os

ICU_SCRIPT = "icu_agent.py"
HOSPITAL_SCRIPT = "hospital_server.py"
AGG_SCRIPT = "aggregator_server.py"

ICUS_PER_HOSP = 3
HOSP_COUNT = 2

HOSP_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3."]
HOSP_PORTS = [8001, 8002, 8003]

class HospitalTopo(Topo):
    def build(self):
        main = self.addSwitch('s1')
        agg = self.addHost('agg', ip='10.0.0.10/24', cpu=.1)
        agg_sw = self.addSwitch('s2')
        self.addLink(agg, agg_sw)
        self.addLink(agg_sw, main, bw=1000)

        self.agg_alias_ips = [f'{subnet}254' for subnet in HOSP_SUBNETS]

        attacker = self.addHost('attacker', ip='10.0.0.99/24', cpu=.5)
        self.addLink(attacker, main, bw=1000)

        for i in range(HOSP_COUNT):
            hs = self.addSwitch(f's{3+i}')
            self.addLink(hs, main, bw=5)
            subnet = HOSP_SUBNETS[i]
            hosp = self.addHost(f'h{i+1}', ip=f'{subnet}1/24', cpu=.05)
            self.addLink(hosp, hs, bw=5)
            for j in range(ICUS_PER_HOSP):
                icu = self.addHost(f'h{i+1}icu{j+1}', ip=f'{subnet}{11+j}/24', cpu=.02)
                self.addLink(icu, hs, bw=1, delay='10ms', loss=0)
            hatt = self.addHost(f'h{i+1}att', ip=f'{subnet}101/24', cpu=.3)
            self.addLink(hatt, hs, bw=1000)

def start_services(net):
    agg = net.get('agg')
    # add alias IPs
    for alias_ip in HOSP_SUBNETS:
        # create alias per subnet (best-effort)
        try:
            agg.cmd(f'ip addr add {alias_ip}254/24 dev agg-eth0 || true')
        except Exception:
            pass

    agg_cmd = f'python3 -u {AGG_SCRIPT} --port 9000 > agg.log 2>&1 &'
    print(f"[mininet] starting aggregator: {agg_cmd}")
    agg.cmd(agg_cmd)
    time.sleep(0.4)

    for i in range(HOSP_COUNT):
        hosp = net.get(f'h{i+1}')
        port = HOSP_PORTS[i]
        agg_ip_alias = f'{HOSP_SUBNETS[i]}254'
        hosp_log = f'{hosp.name}.log'
        # pass iface as host-eth0 (inside mininet host)
        iface_name = f'{hosp.name}-eth0'
        cmd = f'python3 -u {HOSPITAL_SCRIPT} --port {port} --agg_host {agg_ip_alias} --agg_port 9000 --batch 5 --iface {iface_name} --name {hosp.name} > {hosp_log} 2>&1 &'
        print(f"[mininet] starting hospital server {hosp.name} on port {port}: {cmd}")
        hosp.cmd(cmd)
        time.sleep(0.3)

    for i in range(HOSP_COUNT):
        hosp_ip = net.get(f'h{i+1}').IP()
        port = HOSP_PORTS[i]
        for j in range(ICUS_PER_HOSP):
            icu = net.get(f'h{i+1}icu{j+1}')
            icu_log = f'{icu.name}.log'
            interval = 2 + (j % 3)
            cmd = f'python3 -u {ICU_SCRIPT} --host {hosp_ip} --port {port} --id {icu.name} --interval {interval} > {icu_log} 2>&1 &'
            print(f"[mininet] starting ICU agent {icu.name} -> {hosp_ip}:{port}")
            icu.cmd(cmd)
            time.sleep(0.1)

    print("\nServices started: aggregator (agg), hospitals (h1-hN), ICU agents (hXicuY). Logs are unbuffered.")

def main():
    setLogLevel('info')
    topo = HospitalTopo()
    net = Mininet(topo=topo, controller=None, link=TCLink, switch=OVSSwitch, autoSetMacs=True, autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    net.start()
    print("\n✅ Network started successfully.")
    start_services(net)
    print("\n--- Network summary ---")
    print("Aggregator: 10.0.0.10:9000 + alias IPs for each hospital subnet")
    for i in range(HOSP_COUNT):
        print(f"Hospital {i+1}: {HOSP_SUBNETS[i]}1, port {HOSP_PORTS[i]}")
        for j in range(ICUS_PER_HOSP):
            print(f" ICU: {HOSP_SUBNETS[i]}{11+j}")
        print(f" Local attacker: {HOSP_SUBNETS[i]}101")
    print("Global attacker: 10.0.0.99")
    CLI(net)
    print("[mininet_launch] stopping network and killing background processes...")
    for h in net.hosts:
        h.cmd(f'pkill -f {ICU_SCRIPT} || true')
        h.cmd(f'pkill -f {HOSPITAL_SCRIPT} || true')
        h.cmd(f'pkill -f {AGG_SCRIPT} || true')
    net.stop()
    print("Network stopped. ✅")

if __name__ == '__main__':
    main()
