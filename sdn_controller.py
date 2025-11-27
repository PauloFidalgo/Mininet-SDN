#!/usr/bin/env python3
"""
SDN Controller with OpenFlow 1.3 Protocol - Built from Scratch
Includes REST API for Intent-Based Networking
No external SDN frameworks - pure Python implementation
"""

import socket
import struct
import threading
import logging
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

# OpenFlow 1.3 Constants
OFP_VERSION = 0x04

# Message Types
OFPT_HELLO = 0
OFPT_ECHO_REQUEST = 2
OFPT_ECHO_REPLY = 3
OFPT_FEATURES_REQUEST = 5
OFPT_FEATURES_REPLY = 6
OFPT_SET_CONFIG = 9
OFPT_PACKET_IN = 10
OFPT_PACKET_OUT = 13
OFPT_FLOW_MOD = 14

# Flow Mod Commands
OFPFC_ADD = 0
OFPFC_DELETE = 3

# Port Numbers
OFPP_CONTROLLER = 0xfffffffd
OFPP_FLOOD = 0xfffffffb

# Match Types
OFPMT_OXM = 1

# OXM Classes and Fields
OFPXMC_OPENFLOW_BASIC = 0x8000
OFPXMT_OFB_IN_PORT = 0
OFPXMT_OFB_ETH_DST = 3
OFPXMT_OFB_ETH_SRC = 4

# Instructions
OFPIT_APPLY_ACTIONS = 4

# Actions
OFPAT_OUTPUT = 0

# Config Flags
OFPC_FRAG_NORMAL = 0

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OFPMessage:
    """OpenFlow message creation and parsing"""
    
    @staticmethod
    def parse_header(data):
        """Parse OpenFlow header"""
        if len(data) < 8:
            return None
        version, msg_type, length, xid = struct.unpack('!BBHI', data[:8])
        return {
            'version': version,
            'type': msg_type,
            'length': length,
            'xid': xid,
            'data': data[8:length] if len(data) >= length else data[8:]
        }
    
    @staticmethod
    def create_header(msg_type, length, xid=0):
        """Create OpenFlow header"""
        return struct.pack('!BBHI', OFP_VERSION, msg_type, length, xid)
    
    @staticmethod
    def create_hello():
        """Create HELLO message"""
        return OFPMessage.create_header(OFPT_HELLO, 8, 0)
    
    @staticmethod
    def create_echo_reply(xid):
        """Create ECHO_REPLY message"""
        return OFPMessage.create_header(OFPT_ECHO_REPLY, 8, xid)
    
    @staticmethod
    def create_features_request(xid=1):
        """Create FEATURES_REQUEST message"""
        return OFPMessage.create_header(OFPT_FEATURES_REQUEST, 8, xid)
    
    @staticmethod
    def create_set_config(xid=2):
        """Create SET_CONFIG message"""
        header = OFPMessage.create_header(OFPT_SET_CONFIG, 12, xid)
        config = struct.pack('!HH', OFPC_FRAG_NORMAL, 0xffff)
        return header + config
    
    @staticmethod
    def parse_packet_in(data):
        """Parse PACKET_IN message"""
        if len(data) < 24:
            return None
        
        buffer_id, total_len, reason, table_id, cookie = struct.unpack('!IHBBQ', data[:16])
        
        # Parse match to get in_port
        match_type, match_len = struct.unpack('!HH', data[16:20])
        in_port = 0
        
        if match_type == OFPMT_OXM:
            pos = 20
            while pos < 16 + match_len - 4:
                if pos + 4 > len(data):
                    break
                oxm_class_field = struct.unpack('!I', data[pos:pos+4])[0]
                oxm_class = (oxm_class_field >> 16) & 0xffff
                oxm_field = (oxm_class_field >> 9) & 0x7f
                oxm_len = oxm_class_field & 0xff
                
                if oxm_class == OFPXMC_OPENFLOW_BASIC and oxm_field == OFPXMT_OFB_IN_PORT:
                    in_port = struct.unpack('!I', data[pos+4:pos+8])[0]
                
                pos += 4 + oxm_len
        
        # Get packet data
        match_len_padded = (match_len + 7) // 8 * 8
        packet_data_offset = 16 + match_len_padded + 2
        packet_data = data[packet_data_offset:]
        
        return {
            'buffer_id': buffer_id,
            'in_port': in_port,
            'data': packet_data
        }
    
    @staticmethod
    def create_flow_mod(match_fields, actions, priority=1, idle_timeout=0, hard_timeout=0, 
                       buffer_id=0xffffffff, command=OFPFC_ADD):
        """Create FLOW_MOD message"""
        xid = 0
        
        # Build match structure with OXM TLVs
        match_data = b''
        
        if 'in_port' in match_fields:
            oxm = struct.pack('!I', (OFPXMC_OPENFLOW_BASIC << 16) | (OFPXMT_OFB_IN_PORT << 9) | 4)
            oxm += struct.pack('!I', match_fields['in_port'])
            match_data += oxm
        
        if 'eth_src' in match_fields:
            mac = match_fields['eth_src']
            oxm = struct.pack('!I', (OFPXMC_OPENFLOW_BASIC << 16) | (OFPXMT_OFB_ETH_SRC << 9) | 6)
            oxm += bytes.fromhex(mac.replace(':', ''))
            match_data += oxm
        
        if 'eth_dst' in match_fields:
            mac = match_fields['eth_dst']
            oxm = struct.pack('!I', (OFPXMC_OPENFLOW_BASIC << 16) | (OFPXMT_OFB_ETH_DST << 9) | 6)
            oxm += bytes.fromhex(mac.replace(':', ''))
            match_data += oxm
        
        match_len = 4 + len(match_data)
        match_len_padded = (match_len + 7) // 8 * 8
        match = struct.pack('!HH', OFPMT_OXM, match_len) + match_data
        match += b'\x00' * (match_len_padded - match_len)
        
        # Build actions
        action_data = b''
        for action in actions:
            if action['type'] == 'output':
                port = action['port']
                # For CONTROLLER port, set max_len to send full packet
                if port == OFPP_CONTROLLER:
                    max_len = 0xffff  # Send full packet to controller
                else:
                    max_len = 0
                action_data += struct.pack('!HHI', OFPAT_OUTPUT, 16, port)
                action_data += struct.pack('!H6x', max_len)  # max_len + 6 bytes padding
        
        # Build instruction (APPLY_ACTIONS) - only if we have actions
        instruction = b''
        if action_data:
            inst_len = 8 + len(action_data)
            instruction = struct.pack('!HHI', OFPIT_APPLY_ACTIONS, inst_len, 0)
            instruction += action_data
        
        # Build flow_mod message (OpenFlow 1.3 spec section 7.3.4.1)
        flow_mod = struct.pack('!QQ',
            0,  # cookie
            0   # cookie_mask
        )
        flow_mod += struct.pack('!BB',
            0,       # table_id
            command  # command
        )
        flow_mod += struct.pack('!HHH',
            idle_timeout,   # idle_timeout
            hard_timeout,   # hard_timeout
            priority        # priority
        )
        flow_mod += struct.pack('!III',
            buffer_id,      # buffer_id
            0xffffffff,     # out_port
            0xffffffff      # out_group
        )
        flow_mod += struct.pack('!HH',
            0,  # flags
            0   # pad
        )
        
        body = flow_mod + match + instruction
        header = OFPMessage.create_header(OFPT_FLOW_MOD, 8 + len(body), xid)
        
        return header + body
    
    @staticmethod
    def create_packet_out(buffer_id, in_port, actions, data=None):
        """Create PACKET_OUT message"""
        xid = 0
        
        # Build actions
        action_data = b''
        for action in actions:
            if action['type'] == 'output':
                port = action['port']
                if port == OFPP_CONTROLLER:
                    max_len = 0xffff
                else:
                    max_len = 0
                action_data += struct.pack('!HHI', OFPAT_OUTPUT, 16, port)
                action_data += struct.pack('!H6x', max_len)
        
        actions_len = len(action_data)
        packet_out = struct.pack('!IIH6x', buffer_id, in_port, actions_len)
        
        body = packet_out + action_data
        if data:
            body += data
        
        header = OFPMessage.create_header(OFPT_PACKET_OUT, 8 + len(body), xid)
        
        return header + body


class Switch:
    """Represents an OpenFlow switch"""
    
    def __init__(self, connection, address, dpid):
        self.connection = connection
        self.address = address
        self.dpid = dpid
        self.mac_table = {}
        
    def send(self, data):
        """Send data to switch"""
        try:
            self.connection.sendall(data)
            return True
        except:
            return False


class SDNController:
    """Main SDN Controller with OpenFlow and REST API"""
    
    def __init__(self, of_port=6653, api_port=8080):
        self.of_port = of_port
        self.api_port = api_port
        self.switches = {}
        self.intents = []
        self.topology = {
            'switches': {},
            'hosts': {},
        }
        self.running = False
        
    def start(self):
        """Start the controller"""
        self.running = True
        
        # Setup OpenFlow server
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.of_port))
            self.server_socket.listen(5)
        except OSError as e:
            if e.errno == 98:
                logger.error(f"Port {self.of_port} already in use!")
                logger.error("Run: sudo lsof -t -i:6653 | xargs sudo kill -9")
                return
            else:
                raise
        
        logger.info(f"SDN Controller started on port {self.of_port}")
        logger.info(f"REST API starting on port {self.api_port}")
        
        # Start REST API server
        api_thread = threading.Thread(target=self.start_api_server, daemon=True)
        api_thread.start()
        
        logger.info("Ready to accept switch connections...")
        
        # Main loop - accept OpenFlow connections
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"New switch connection from {address}")
                
                thread = threading.Thread(target=self.handle_switch, 
                                        args=(client_socket, address))
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                logger.info("\nShutting down...")
                break
            except Exception as e:
                logger.error(f"Error: {e}")
        
        self.stop()
    
    def handle_switch(self, connection, address):
        """Handle OpenFlow switch connection"""
        dpid = None
        switch = None
        
        try:
            # OpenFlow handshake
            connection.sendall(OFPMessage.create_hello())
            logger.info(f"Sent HELLO to {address}")
            
            data = connection.recv(4096)
            if data:
                msg = OFPMessage.parse_header(data)
                if msg and msg['type'] == OFPT_HELLO:
                    logger.info(f"Received HELLO from {address}")
            
            # Get switch features
            connection.sendall(OFPMessage.create_features_request())
            
            data = connection.recv(4096)
            if data:
                msg = OFPMessage.parse_header(data)
                if msg and msg['type'] == OFPT_FEATURES_REPLY:
                    dpid = struct.unpack('!Q', msg['data'][:8])[0]
                    logger.info(f"Switch DPID: {dpid}")
                    
                    switch = Switch(connection, address, dpid)
                    self.switches[dpid] = switch
                    self.topology['switches'][dpid] = {
                        'dpid': dpid,
                        'address': str(address)
                    }
                    
                    connection.sendall(OFPMessage.create_set_config())
                    self.install_table_miss(switch)
            
            # Only continue if switch was created successfully
            if switch is None:
                logger.error(f"Failed to initialize switch from {address}")
                return
            
            # Message processing loop
            buffer = b''
            while self.running:
                data = connection.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                while len(buffer) >= 8:
                    msg = OFPMessage.parse_header(buffer)
                    if not msg or len(buffer) < msg['length']:
                        break
                    
                    self.process_message(switch, msg)
                    buffer = buffer[msg['length']:]
        
        except Exception as e:
            logger.error(f"Error handling switch: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if dpid and dpid in self.switches:
                del self.switches[dpid]
                logger.info(f"Switch {dpid} disconnected")
            connection.close()
    
    def process_message(self, switch, msg):
        """Process OpenFlow message"""
        msg_type = msg['type']
        
        if msg_type == OFPT_ECHO_REQUEST:
            switch.send(OFPMessage.create_echo_reply(msg['xid']))
        elif msg_type == OFPT_PACKET_IN:
            self.handle_packet_in(switch, msg)
        elif msg_type == OFPT_ERROR:
            # Parse error message
            error_type = struct.unpack('!H', msg['data'][:2])[0] if len(msg['data']) >= 2 else 0
            error_code = struct.unpack('!H', msg['data'][2:4])[0] if len(msg['data']) >= 4 else 0
            logger.error(f"OpenFlow ERROR from switch {switch.dpid}: type={error_type}, code={error_code}")
            logger.error(f"Error data: {msg['data'][:32].hex()}")
        else:
            logger.debug(f"Received message type {msg_type} from switch {switch.dpid}")
    
    def handle_packet_in(self, switch, msg):
        """Handle PACKET_IN message"""
        packet_in = OFPMessage.parse_packet_in(msg['data'])
        if not packet_in:
            return
        
        in_port = packet_in['in_port']
        data = packet_in['data']
        buffer_id = packet_in['buffer_id']
        
        # Parse Ethernet frame
        if len(data) < 14:
            return
        
        eth_dst = ':'.join(f'{b:02x}' for b in data[0:6])
        eth_src = ':'.join(f'{b:02x}' for b in data[6:12])
        
        logger.info(f"PACKET_IN: Switch={switch.dpid} {eth_src} -> {eth_dst} port={in_port}")
        
        # Learn MAC address
        switch.mac_table[eth_src] = in_port
        
        # Update topology
        if eth_src not in self.topology['hosts']:
            self.topology['hosts'][eth_src] = {
                'mac': eth_src,
                'switch': switch.dpid,
                'port': in_port
            }
        
        # Check intents
        out_port = self.check_intents(switch.dpid, eth_src, eth_dst, in_port)
        
        if out_port is None:
            # Normal learning switch
            if eth_dst in switch.mac_table:
                out_port = switch.mac_table[eth_dst]
            else:
                out_port = OFPP_FLOOD
        
        # Install flow if not flooding
        if out_port != OFPP_FLOOD and out_port is not None:
            # Get priority from intents
            priority = self.get_intent_priority(eth_src, eth_dst)
            
            match = {
                'in_port': in_port,
                'eth_src': eth_src,
                'eth_dst': eth_dst
            }
            actions = [{'type': 'output', 'port': out_port}]
            
            # If there's a priority intent, make flow permanent (no timeout)
            if priority != 10:
                flow_mod = OFPMessage.create_flow_mod(match, actions, priority=priority, idle_timeout=0, hard_timeout=0)
                logger.info(f"Flow installed: {eth_src} -> {eth_dst} out_port={out_port} priority={priority} (PERMANENT)")
            else:
                flow_mod = OFPMessage.create_flow_mod(match, actions, priority=priority, idle_timeout=30)
                logger.info(f"Flow installed: {eth_src} -> {eth_dst} out_port={out_port} priority={priority}")
            
            switch.send(flow_mod)
        
        # Send packet out
        if out_port is not None:
            actions = [{'type': 'output', 'port': out_port}]
            packet_out = OFPMessage.create_packet_out(
                buffer_id, in_port, actions, 
                data if buffer_id == 0xffffffff else None
            )
            switch.send(packet_out)
    
    def install_table_miss(self, switch):
        """Install table-miss flow entry"""
        logger.info(f"Creating table-miss flow for switch {switch.dpid}")
        
        match = {}
        actions = [{'type': 'output', 'port': OFPP_CONTROLLER}]
        flow_mod = OFPMessage.create_flow_mod(match, actions, priority=0)
        
        # Debug output
        logger.info(f"Flow mod message length: {len(flow_mod)} bytes")
        logger.info(f"Flow mod hex (first 64 bytes): {flow_mod[:64].hex()}")
        
        result = switch.send(flow_mod)
        if result:
            logger.info(f"Table-miss flow sent successfully to switch {switch.dpid}")
        else:
            logger.error(f"Failed to send table-miss flow to switch {switch.dpid}")
        
        # Wait a bit and verify
        import time
        time.sleep(0.1)
    
    def check_intents(self, dpid, src, dst, in_port):
        """Check if any intent rules apply"""
        for intent in self.intents:
            if not intent.get('enabled', True):
                continue  # Skip disabled intents
            
            if intent['type'] == 'block':
                if (intent.get('src_mac') == src and intent.get('dst_mac') == dst):
                    logger.info(f"Intent BLOCK: {src} -> {dst}")
                    return None
            
            elif intent['type'] == 'redirect':
                if (intent.get('src_mac') == src and intent.get('dst_mac') == dst):
                    new_port = intent.get('out_port')
                    logger.info(f"Intent REDIRECT: {src} -> {dst} via port {new_port}")
                    return new_port
        
        return None
    
    def get_intent_priority(self, src, dst):
        """Get priority for traffic from intent rules"""
        for intent in self.intents:
            if not intent.get('enabled', True):
                continue
            
            if intent['type'] == 'priority':
                if (intent.get('src_mac') == src and intent.get('dst_mac') == dst):
                    return intent.get('priority', 10)
        
        return 10  # Default priority
    
    def add_intent(self, intent):
        """Add a new intent"""
        # Generate intent ID if not provided
        if 'id' not in intent:
            intent['id'] = len(self.intents) + 1
        
        # Set enabled flag if not provided
        if 'enabled' not in intent:
            intent['enabled'] = True
        
        self.intents.append(intent)
        logger.info(f"Intent added: {intent}")
        
        # Apply intent immediately based on type
        if intent['enabled']:
            if intent['type'] == 'block':
                self.apply_block_intent(intent)
            elif intent['type'] == 'priority':
                self.apply_priority_intent(intent)
            elif intent['type'] == 'redirect':
                self.apply_redirect_intent(intent)
        
        return intent
    
    def apply_redirect_intent(self, intent):
        """Apply redirect intent to all switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        out_port = intent.get('out_port')
        
        for dpid, switch in self.switches.items():
            # First, delete any existing flows for this src/dst pair
            match_delete = {'eth_src': src_mac, 'eth_dst': dst_mac}
            flow_delete = OFPMessage.create_flow_mod(match_delete, [], priority=10, command=OFPFC_DELETE)
            switch.send(flow_delete)
            logger.info(f"Deleted existing flows for {src_mac} -> {dst_mac} on switch {dpid}")
            
            # Get source port if known
            src_port = switch.mac_table.get(src_mac)
            
            if src_port:
                # Install redirect flow with high priority
                match = {
                    'in_port': src_port,
                    'eth_src': src_mac,
                    'eth_dst': dst_mac
                }
                actions = [{'type': 'output', 'port': out_port}]
                # Use high priority to override normal forwarding
                flow_mod = OFPMessage.create_flow_mod(match, actions, priority=50, idle_timeout=0, hard_timeout=0)
                switch.send(flow_mod)
                logger.info(f"Redirect flow installed on switch {dpid}: {src_mac} -> {dst_mac} via port {out_port} (priority=50, permanent)")
            else:
                logger.info(f"Redirect intent registered for {src_mac} -> {dst_mac}, will apply when topology is learned")
    
    def apply_priority_intent(self, intent):
        """Apply priority intent to all switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        priority = intent.get('priority', 10)
        
        for dpid, switch in self.switches.items():
            # Check if we know the ports for these MACs
            src_port = None
            dst_port = None
            
            # Check if MACs are in the switch's MAC table
            if src_mac in switch.mac_table:
                src_port = switch.mac_table[src_mac]
            if dst_mac in switch.mac_table:
                dst_port = switch.mac_table[dst_mac]
            
            # If we don't know the ports yet, the priority will be applied when traffic flows
            if src_port and dst_port:
                match = {
                    'in_port': src_port,
                    'eth_src': src_mac,
                    'eth_dst': dst_mac
                }
                actions = [{'type': 'output', 'port': dst_port}]
                # Install with NO idle timeout so priority persists
                flow_mod = OFPMessage.create_flow_mod(match, actions, priority=priority, idle_timeout=0, hard_timeout=0)
                switch.send(flow_mod)
                logger.info(f"Priority flow installed on switch {dpid}: {src_mac} -> {dst_mac} priority={priority}")
            else:
                logger.info(f"Priority intent registered, will apply when topology is learned")
    
    def remove_intent(self, intent_id):
        """Remove an intent by ID"""
        for i, intent in enumerate(self.intents):
            if intent.get('id') == intent_id:
                removed = self.intents.pop(i)
                logger.info(f"Intent removed: {removed}")
                
                # Clear flows if it was a block intent
                if removed['type'] == 'block':
                    self.clear_block_intent(removed)
                
                return removed
        return None
    
    def enable_intent(self, intent_id):
        """Enable an intent"""
        for intent in self.intents:
            if intent.get('id') == intent_id:
                intent['enabled'] = True
                logger.info(f"Intent enabled: {intent}")
                
                if intent['type'] == 'block':
                    self.apply_block_intent(intent)
                elif intent['type'] == 'priority':
                    self.apply_priority_intent(intent)
                elif intent['type'] == 'redirect':
                    self.apply_redirect_intent(intent)
                
                return intent
        return None
    
    def disable_intent(self, intent_id):
        """Disable an intent"""
        for intent in self.intents:
            if intent.get('id') == intent_id:
                intent['enabled'] = False
                logger.info(f"Intent disabled: {intent}")
                
                if intent['type'] == 'block':
                    self.clear_block_intent(intent)
                elif intent['type'] == 'priority':
                    self.clear_priority_intent(intent)
                elif intent['type'] == 'redirect':
                    self.clear_redirect_intent(intent)
                
                return intent
        return None
    
    def clear_redirect_intent(self, intent):
        """Remove redirect flows from switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        
        for dpid, switch in self.switches.items():
            match = {'eth_src': src_mac, 'eth_dst': dst_mac}
            flow_mod = OFPMessage.create_flow_mod(match, [], priority=50, command=OFPFC_DELETE)
            switch.send(flow_mod)
            logger.info(f"Redirect rule removed from switch {dpid}")
    
    def clear_priority_intent(self, intent):
        """Remove priority flows from switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        
        for dpid, switch in self.switches.items():
            match = {'eth_src': src_mac, 'eth_dst': dst_mac}
            # Send flow_mod with DELETE command
            flow_mod = OFPMessage.create_flow_mod(match, [], priority=intent.get('priority', 10), command=OFPFC_DELETE)
            switch.send(flow_mod)
            logger.info(f"Priority rule removed from switch {dpid}")
    
    def clear_block_intent(self, intent):
        """Remove block flows from switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        
        for dpid, switch in self.switches.items():
            match = {'eth_src': src_mac, 'eth_dst': dst_mac}
            # Send flow_mod with DELETE command
            flow_mod = OFPMessage.create_flow_mod(match, [], priority=100, command=OFPFC_DELETE)
            switch.send(flow_mod)
            logger.info(f"Block rule removed from switch {dpid}")
    
    def apply_block_intent(self, intent):
        """Apply block intent to all switches"""
        src_mac = intent.get('src_mac')
        dst_mac = intent.get('dst_mac')
        
        for dpid, switch in self.switches.items():
            match = {'eth_src': src_mac, 'eth_dst': dst_mac}
            actions = []  # Empty actions = drop
            flow_mod = OFPMessage.create_flow_mod(match, actions, priority=100)
            switch.send(flow_mod)
            logger.info(f"Block rule installed on switch {dpid}")
    
    def start_api_server(self):
        """Start REST API server"""
        controller = self
        
        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/api/topology':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps(controller.topology, indent=2)
                    self.wfile.write(response.encode())
                
                elif self.path == '/api/intents':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps({'intents': controller.intents}, indent=2)
                    self.wfile.write(response.encode())
                
                elif self.path.startswith('/api/flows/'):
                    dpid = int(self.path.split('/')[-1])
                    if dpid in controller.switches:
                        switch = controller.switches[dpid]
                        response = {
                            'dpid': dpid,
                            'mac_table': switch.mac_table
                        }
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(response, indent=2).encode())
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                elif self.path == '/api/stats':
                    # Network statistics
                    stats = {
                        'switches': len(controller.switches),
                        'hosts': len(controller.topology['hosts']),
                        'intents': len(controller.intents),
                        'active_intents': sum(1 for i in controller.intents if i.get('enabled', True))
                    }
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(stats, indent=2).encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/api/intents':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    intent = json.loads(post_data.decode())
                    
                    result = controller.add_intent(intent)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response = json.dumps({'status': 'success', 'intent': result}, indent=2)
                    self.wfile.write(response.encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_DELETE(self):
                if self.path.startswith('/api/intents/'):
                    intent_id = int(self.path.split('/')[-1])
                    removed = controller.remove_intent(intent_id)
                    
                    if removed:
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        response = json.dumps({'status': 'success', 'removed': removed}, indent=2)
                        self.wfile.write(response.encode())
                    else:
                        self.send_response(404)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        response = json.dumps({'status': 'error', 'message': 'Intent not found'})
                        self.wfile.write(response.encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_PUT(self):
                if self.path.startswith('/api/intents/') and '/enable' in self.path:
                    intent_id = int(self.path.split('/')[-2])
                    enabled = controller.enable_intent(intent_id)
                    
                    if enabled:
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        response = json.dumps({'status': 'success', 'intent': enabled}, indent=2)
                        self.wfile.write(response.encode())
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                elif self.path.startswith('/api/intents/') and '/disable' in self.path:
                    intent_id = int(self.path.split('/')[-2])
                    disabled = controller.disable_intent(intent_id)
                    
                    if disabled:
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        response = json.dumps({'status': 'success', 'intent': disabled}, indent=2)
                        self.wfile.write(response.encode())
                    else:
                        self.send_response(404)
                        self.end_headers()
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass
        
        try:
            api_server = HTTPServer(('0.0.0.0', self.api_port), APIHandler)
            # Set SO_REUSEADDR to avoid "Address already in use" errors
            api_server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.info(f"REST API server started on port {self.api_port}")
            api_server.serve_forever()
        except OSError as e:
            if e.errno == 98:
                logger.error(f"Port {self.api_port} already in use!")
                logger.error("Run: sudo lsof -t -i:8080 | xargs sudo kill -9")
            else:
                logger.error(f"API server error: {e}")
    
    def stop(self):
        """Stop the controller"""
        self.running = False
        for switch in self.switches.values():
            switch.connection.close()
        self.server_socket.close()
        logger.info("Controller stopped")


if __name__ == '__main__':
    controller = SDNController(of_port=6653, api_port=8080)
    try:
        controller.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        controller.stop()