# ryu_ddos_blocker_full.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

# ---------------- Ryu app ---------------- #

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_alert_count = {}      # track alerts per IP
        self.block_threshold = 5      # block after 5 alerts
        self.datapaths = {}           # track all connected switches

        wsgi = kwargs['wsgi']
        wsgi.register(DDoSController, {'ryu_app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath  # track datapath
        self.logger.info(f"Switch connected: dpid={datapath.id}")

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == "DEAD" and datapath.id in self.datapaths:
            del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def block_ip(self, ip):
        """
        Install drop flows for the given IP on all connected switches
        """
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            actions = []  # drop
            self.add_flow(dp, priority=100, match=match, actions=actions)

        self.logger.info(f"Blocked IP {ip} on all switches")

# ---------------- WSGI REST controller ---------------- #

class DDoSController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(DDoSController, self).__init__(req, link, data, **config)
        self.ryu_app = data['ryu_app']

    @route('ddos', '/ddos_alert', methods=['POST'])
    def ddos_alert(self, req, **kwargs):
        try:
            data = json.loads(req.body)
            ip = data.get("dominant_src") or data.get("ip")
            if not ip:
                return Response(status=400, body=json.dumps({"error": "missing ip"}))

            # increment alert counter
            count = self.ryu_app.ip_alert_count.get(ip, 0) + 1
            self.ryu_app.ip_alert_count[ip] = count
            self.ryu_app.logger.info(f"DDoS alert for {ip} -> count={count}")

            if count >= self.ryu_app.block_threshold:
                self.ryu_app.block_ip(ip)
                return Response(status=200, body=json.dumps({"status": f"IP {ip} blocked"}))

            return Response(status=200, body=json.dumps({"status": "alert recorded"}))
        except Exception as e:
            self.ryu_app.logger.error(f"Failed to process DDoS alert: {e}")
            return Response(status=500, body=json.dumps({"error": str(e)}))
