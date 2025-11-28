from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob.response import Response
import json

INTENT_URL = "/intents/v1/intents"

class IntentController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs["wsgi"]

        self.mac_to_port = {}
        self.intents = {}
        self.datapaths = {}

        wsgi.register(IntentRest, {"app": self})

    def add_datapath(self, dp):
        self.datapaths[dp.id] = dp

    def install_flow(self, dp, priority, match, actions, table_id=0):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        # If actions is empty, create a drop (no instructions)
        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []

        mod = parser.OFPFlowMod(
            datapath=dp,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        self.add_datapath(dp)
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.install_flow(dp, 0, match, actions)

        # Install a low-priority permissive flow to let OVS handle basic L2 forwarding
        # This makes the network usable by default while intent flows (higher priority)
        # can still install overrides (e.g., drops at priority 100).
        try:
            permissive_actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self.install_flow(dp, 1, parser.OFPMatch(), permissive_actions)
            self.logger.info("Installed permissive NORMAL flow on %s", dp.id)
        except Exception as e:
            self.logger.warning("Failed to install permissive flow on %s: %s", dp.id, e)

        self.logger.info("Switch connected: %s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        self.logger.debug("PacketIn dpid=%s in_port=%s eth_src=%s eth_dst=%s eth_type=0x%04x",
                          dp.id, msg.match.get('in_port'), eth.src, eth.dst, eth.ethertype)

        if eth.ethertype == 0x88cc:  # Ignore LLDP
            return

        dpid = dp.id
        src = eth.src
        dst = eth.dst
        in_port = msg.match["in_port"]

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Check if this traffic should be blocked by any intent
        if self._should_block(src, dst, pkt):
            self.logger.info("Blocking packet from %s to %s", src, dst)
            return

        # Normal forwarding logic
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow only if we know the destination
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.install_flow(dp, 10, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    def _should_block(self, src, dst, pkt):
        """Check if any block intent matches this traffic"""
        for intent_id, intent in self.intents.items():
            if intent["type"] == "block":
                if self._matches_intent(intent, src, dst, pkt):
                    return True
        return False

    def _matches_intent(self, intent, src, dst, pkt):
        """Check if packet matches intent criteria"""
        # Check MAC addresses
        if intent.get("src") and intent["src"] != src:
            return False
        if intent.get("dst") and intent["dst"] != dst:
            return False
        
        # Check protocol if specified
        if intent.get("protocol"):
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if not ip_pkt:
                return False
                
            if intent["protocol"] == "tcp":
                if not pkt.get_protocol(tcp.tcp):
                    return False
            elif intent["protocol"] == "udp":
                if not pkt.get_protocol(udp.udp):
                    return False
        
        # Check port if specified
        if intent.get("dst_port"):
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                if intent.get("protocol") == "tcp":
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt and tcp_pkt.dst_port != intent["dst_port"]:
                        return False
                elif intent.get("protocol") == "udp":
                    udp_pkt = pkt.get_protocol(udp.udp)
                    if udp_pkt and udp_pkt.dst_port != intent["dst_port"]:
                        return False
        
        return True

    def apply_intent_to_switch(self, dp, intent):
        """Apply intent to a specific switch"""
        parser = dp.ofproto_parser
        
        if intent["type"] == "block":
            # Create match for block
            match_dict = {
                'eth_src': intent["src"],
                'eth_dst': intent["dst"]
            }
            
            # Add protocol matching if specified
            if intent.get("protocol"):
                match_dict['eth_type'] = 0x0800  # IPv4
                if intent["protocol"] == "tcp":
                    match_dict['ip_proto'] = 6
                elif intent["protocol"] == "udp":
                    match_dict['ip_proto'] = 17
            
            # Add port matching if specified
            if intent.get("dst_port"):
                if intent.get("protocol") == "tcp":
                    match_dict['tcp_dst'] = intent["dst_port"]
                elif intent.get("protocol") == "udp":
                    match_dict['udp_dst'] = intent["dst_port"]
            
            match = parser.OFPMatch(**match_dict)
            actions = []  # Empty actions = drop
            self.install_flow(dp, 100, match, actions)
            
        elif intent["type"] == "unblock":
            # For unblock, we need to remove any blocking flows
            # This is simplified - in production you'd track flow cookies
            pass
            
        elif intent["type"] == "prioritize":
            match_dict = {
                'eth_src': intent["src"],
                'eth_dst': intent["dst"],
                'eth_type': 0x0800
            }
            
            if intent.get("protocol"):
                if intent["protocol"] == "tcp":
                    match_dict['ip_proto'] = 6
                elif intent["protocol"] == "udp":
                    match_dict['ip_proto'] = 17
            
            if intent.get("dst_port"):
                if intent.get("protocol") == "tcp":
                    match_dict['tcp_dst'] = intent["dst_port"]
                elif intent.get("protocol") == "udp":
                    match_dict['udp_dst'] = intent["dst_port"]
            
            match = parser.OFPMatch(**match_dict)
            actions = [
                parser.OFPActionSetField(ip_dscp=intent.get("dscp", 46)),
                parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)
            ]
            self.install_flow(dp, 90, match, actions)
            
        elif intent["type"] == "redirect":
            match_dict = {
                'eth_src': intent["src"],
                'eth_dst': intent["dst"]
            }
            
            if intent.get("protocol"):
                match_dict['eth_type'] = 0x0800
                if intent["protocol"] == "tcp":
                    match_dict['ip_proto'] = 6
                elif intent["protocol"] == "udp":
                    match_dict['ip_proto'] = 17
            
            if intent.get("dst_port"):
                if intent.get("protocol") == "tcp":
                    match_dict['tcp_dst'] = intent["dst_port"]
                elif intent.get("protocol") == "udp":
                    match_dict['udp_dst'] = intent["dst_port"]
            
            match = parser.OFPMatch(**match_dict)
            actions = [parser.OFPActionOutput(intent["out_port"])]
            self.install_flow(dp, 80, match, actions)

    def remove_intent_from_switch(self, dp, intent):
        """Remove intent flows from switch"""
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        
        # Create the same match criteria used when installing
        match_dict = {
            'eth_src': intent["src"],
            'eth_dst': intent["dst"]
        }
        
        if intent.get("protocol"):
            match_dict['eth_type'] = 0x0800
            if intent["protocol"] == "tcp":
                match_dict['ip_proto'] = 6
            elif intent["protocol"] == "udp":
                match_dict['ip_proto'] = 17
        
        if intent.get("dst_port"):
            if intent.get("protocol") == "tcp":
                match_dict['tcp_dst'] = intent["dst_port"]
            elif intent.get("protocol") == "udp":
                match_dict['udp_dst'] = intent["dst_port"]
        
        match = parser.OFPMatch(**match_dict)
        
        # Delete flows with this match
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match
        )
        dp.send_msg(mod)


class IntentRest(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data["app"]

    @route("intent", INTENT_URL, methods=["GET"])
    def list(self, req):
        return Response(json_body=self.app.intents)

    @route("intent", INTENT_URL, methods=["POST"])
    def add(self, req):
        try:
            data = req.json_body
            intent_id = data["id"]

            self.app.intents[intent_id] = data

            # Apply intent to all switches
            for dp in self.app.datapaths.values():
                self.app.apply_intent_to_switch(dp, data)

            return Response(json_body={"status": "installed"}, status=201)
        except Exception as e:
            self.app.logger.error("Error adding intent: %s", e)
            return Response(json_body={"error": str(e)}, status=400)

    @route("intent", INTENT_URL + "/{intent_id}", methods=["DELETE"])
    def delete(self, req, intent_id):
        try:
            if intent_id in self.app.intents:
                intent = self.app.intents[intent_id]
                
                # Remove from all switches
                for dp in self.app.datapaths.values():
                    self.app.remove_intent_from_switch(dp, intent)
                
                del self.app.intents[intent_id]

            return Response(json_body={"status": "deleted"}, status=200)
        except Exception as e:
            self.app.logger.error("Error deleting intent: %s", e)
            return Response(json_body={"error": str(e)}, status=400)