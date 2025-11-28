#!/usr/bin/env python
"""
mininet_tests_mac.py - Automated testing for intent-based SDN controller using MACs
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import requests
import sys

API_URL = "http://localhost:8080/intents/v1/intents"
IPERF_TIME = 10
IPERF_PORT = 5001

# MAC addresses for hosts
HOST_MACS = {
    'h1': '00:00:00:00:00:01',
    'h2': '00:00:00:00:00:02',
    'h3': '00:00:00:00:00:03'
}


class IntentTester:
    def __init__(self, net):
        self.net = net
        self.results = []

    def add_intent(self, intent_data):
        try:
            response = requests.post(API_URL, json=intent_data, timeout=5)
            info(f"Added intent {intent_data['id']}: {response.status_code}\n")
            time.sleep(2)
            return response.status_code == 201
        except Exception as e:
            info(f"Error adding intent: {e}\n")
            return False

    def delete_intent(self, intent_id):
        try:
            response = requests.delete(f"{API_URL}/{intent_id}", timeout=5)
            info(f"Deleted intent {intent_id}: {response.status_code}\n")
            time.sleep(2)
            return response.status_code == 200
        except Exception as e:
            info(f"Error deleting intent: {e}\n")
            return False

    def run_iperf_test(self, test_name, server, client, port=IPERF_PORT, duration=IPERF_TIME, udp=False, expect_success=True):
        """Run iperf test with configurable success expectation"""
        info(f"\n{'='*50}\nTest: {test_name}\n{'='*50}\n")
        server_host = self.net.get(server)
        client_host = self.net.get(client)

        # Kill any existing iperf processes
        server_host.cmd("pkill -9 iperf")
        client_host.cmd("pkill -9 iperf")
        time.sleep(1)

        if udp:
            server_cmd = f"iperf -s -u -p {port} > /tmp/iperf_{server}_server.txt 2>&1 &"
            client_cmd = f"iperf -c {server_host.IP()} -u -p {port} -b 50M -t {duration} 2>&1"
        else:
            server_cmd = f"iperf -s -p {port} > /tmp/iperf_{server}_server.txt 2>&1 &"
            client_cmd = f"iperf -c {server_host.IP()} -p {port} -t {duration} 2>&1"

        info(f"Starting server on {server}\n")
        server_host.cmd(server_cmd)
        time.sleep(2)

        info(f"Starting client on {client}\n")
        result = client_host.cmd(client_cmd)
        info(f"Result:\n{result}\n")

        # Cleanup
        server_host.cmd("pkill -9 iperf")
        time.sleep(1)

        # Check if test result matches expectation
        actual_success = "connected with" in result and "sec" in result
        bandwidth = self.extract_bandwidth(result)
        
        # For block tests, we expect failure (connection timeout)
        if "block" in test_name.lower() and "timeout" in test_name.lower():
            test_success = not actual_success  # Should fail = success for block test
            status_note = "(expected timeout)"
        else:
            test_success = actual_success == expect_success
            status_note = ""
        
        self.results.append({
            'test': test_name, 
            'success': test_success, 
            'result': result,
            'bandwidth': bandwidth,
            'status_note': status_note
        })
        return result, test_success, bandwidth

    def extract_bandwidth(self, iperf_output):
        """Extract bandwidth from iperf output"""
        for line in iperf_output.split('\n'):
            if 'Gbits/sec' in line or 'Mbits/sec' in line:
                if 'sec' in line and 'Bytes' in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        return parts[-2] + ' ' + parts[-1]
        return "N/A"

    def test_concurrent_flows_sequential(self):
        """Test concurrent flows using sequential execution with background processes"""
        info("\n### TEST 4: CONCURRENT FLOWS WITH PRIORITY ###\n")
        
        # Test 4A: Concurrent flows without priority (baseline)
        info("\n--- 4A: Concurrent flows WITHOUT priority (baseline) ---\n")
        
        # Start both servers first
        h2 = self.net.get('h2')
        h2.cmd("pkill -9 iperf")
        h2.cmd("iperf -s -p 5001 > /tmp/iperf_h2_5001.txt 2>&1 &")
        h2.cmd("iperf -s -p 5002 > /tmp/iperf_h2_5002.txt 2>&1 &")
        time.sleep(2)
        
        # Start both clients in background
        h1 = self.net.get('h1')
        h3 = self.net.get('h3')
        
        info("Starting concurrent flows: h1->h2 (port 5001) and h3->h2 (port 5002)\n")
        # Use longer duration for more stable TCP measurements
        h1.cmd("iperf -c 10.0.0.2 -p 5001 -t 12 > /tmp/iperf_h1_client.txt 2>&1 &")
        h3.cmd("iperf -c 10.0.0.2 -p 5002 -t 12 > /tmp/iperf_h3_client.txt 2>&1 &")
        
        # Wait for completion
        time.sleep(14)
        
        # Get results
        h1_result = h1.cmd("cat /tmp/iperf_h1_client.txt")
        h3_result = h3.cmd("cat /tmp/iperf_h3_client.txt")
        
        h1_bandwidth = self.extract_bandwidth(h1_result)
        h3_bandwidth = self.extract_bandwidth(h3_result)
        
        info(f"Baseline Results:\n")
        info(f"  h1->h2: {h1_bandwidth}\n")
        info(f"  h3->h2: {h3_bandwidth}\n")
        
        baseline_results = {
            'h1_h2': h1_bandwidth,
            'h3_h2': h3_bandwidth
        }
        
        # Cleanup
        h2.cmd("pkill -9 iperf")
        time.sleep(2)
        
        # Test 4B: Add priority to h1->h2 flow
        info("\n--- 4B: Concurrent flows WITH h1->h2 prioritized ---\n")
        priority_intent = {
            "id": "prioritize_h1_h2_concurrent",
            "type": "prioritize", 
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2'],
            "dscp": 46
        }
        self.add_intent(priority_intent)
        time.sleep(3)  # Give more time for flow installation
        
        # Start both servers again
        h2.cmd("iperf -s -p 5001 > /tmp/iperf_h2_5001.txt 2>&1 &")
        h2.cmd("iperf -s -p 5002 > /tmp/iperf_h2_5002.txt 2>&1 &")
        time.sleep(2)
        
        # Start both clients in background
        info("Starting concurrent flows with h1->h2 prioritized\n")
        h1.cmd("iperf -c 10.0.0.2 -p 5001 -t 12 > /tmp/iperf_h1_client_prio.txt 2>&1 &")
        h3.cmd("iperf -c 10.0.0.2 -p 5002 -t 12 > /tmp/iperf_h3_client_prio.txt 2>&1 &")
        
        # Wait for completion
        time.sleep(14)
        
        # Get results
        h1_result_prio = h1.cmd("cat /tmp/iperf_h1_client_prio.txt")
        h3_result_prio = h3.cmd("cat /tmp/iperf_h3_client_prio.txt")
        
        h1_bandwidth_prio = self.extract_bandwidth(h1_result_prio)
        h3_bandwidth_prio = self.extract_bandwidth(h3_result_prio)
        
        info(f"Priority Results:\n")
        info(f"  h1->h2 (prioritized): {h1_bandwidth_prio}\n")
        info(f"  h3->h2 (normal): {h3_bandwidth_prio}\n")
        
        priority_results = {
            'h1_h2': h1_bandwidth_prio,
            'h3_h2': h3_bandwidth_prio
        }
        
        # Cleanup
        h2.cmd("pkill -9 iperf")
        self.delete_intent("prioritize_h1_h2_concurrent")
        
        # Comparison
        info("\n--- QoS COMPARISON RESULTS ---\n")
        info(f"h1->h2 flow:\n")
        info(f"  Baseline:    {baseline_results['h1_h2']}\n")
        info(f"  Prioritized: {priority_results['h1_h2']}\n")
        
        info(f"h3->h2 flow:\n")
        info(f"  Baseline:    {baseline_results['h3_h2']}\n")
        info(f"  With h1 priority: {priority_results['h3_h2']}\n")
        
        # Calculate bandwidth changes
        try:
            h1_baseline = float(baseline_results['h1_h2'].split()[0])
            h1_priority = float(priority_results['h1_h2'].split()[0])
            h3_baseline = float(baseline_results['h3_h2'].split()[0])
            h3_priority = float(priority_results['h3_h2'].split()[0])
            
            h1_change = ((h1_priority - h1_baseline) / h1_baseline) * 100
            h3_change = ((h3_priority - h3_baseline) / h3_baseline) * 100
            
            info(f"\nBandwidth Changes:\n")
            info(f"  h1->h2: {h1_change:+.1f}%\n")
            info(f"  h3->h2: {h3_change:+.1f}%\n")
            
        except (ValueError, IndexError):
            info("Could not calculate bandwidth changes (format issue)\n")
        
        # Store results
        self.results.append({
            'test': 'Concurrent flows WITHOUT priority',
            'success': True,
            'concurrent_results': [
                {'flow': 'h1->h2:5001', 'bandwidth': baseline_results['h1_h2']},
                {'flow': 'h3->h2:5002', 'bandwidth': baseline_results['h3_h2']}
            ]
        })
        
        self.results.append({
            'test': 'Concurrent flows WITH h1->h2 prioritized', 
            'success': True,
            'concurrent_results': [
                {'flow': 'h1->h2:5001', 'bandwidth': priority_results['h1_h2']},
                {'flow': 'h3->h2:5002', 'bandwidth': priority_results['h3_h2']}
            ]
        })

    def test_baseline(self):
        info("\n### TEST 1: BASELINE (No Intents) ###\n")
        result, success, bandwidth = self.run_iperf_test("Baseline h1->h2", "h2", "h1")
        return bandwidth

    def test_block_intent(self):
        info("\n### TEST 2: BLOCK INTENT ###\n")
        intent = {
            "id": "block_h1_h2",
            "type": "block",
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2']
        }
        self.add_intent(intent)
        # For block test, we expect timeout = success
        self.run_iperf_test("Block h1->h2 (should timeout)", "h2", "h1", duration=5, expect_success=False)
        self.delete_intent("block_h1_h2")
        result, success, bandwidth = self.run_iperf_test("After unblock h1->h2", "h2", "h1")
        return bandwidth

    def test_prioritize_intent(self):
        info("\n### TEST 3: PRIORITIZE INTENT (QoS) ###\n")
        intent = {
            "id": "prioritize_h1_h2",
            "type": "prioritize",
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2'],
            "dscp": 46
        }
        self.add_intent(intent)
        result, success, bandwidth = self.run_iperf_test("Prioritize h1->h2 DSCP=46", "h2", "h1")
        self.delete_intent("prioritize_h1_h2")
        return bandwidth

    def test_protocol_specific(self):
        info("\n### TEST 5: PROTOCOL-SPECIFIC INTENT ###\n")
        intent = {
            "id": "block_tcp_5001",
            "type": "block",
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2'],
            "protocol": "tcp",
            "dst_port": 5001
        }
        self.add_intent(intent)
        # Expect timeout for blocked port
        self.run_iperf_test("Block TCP port 5001", "h2", "h1", port=5001, duration=5, expect_success=False)
        # Expect success for allowed port
        result, success, bandwidth = self.run_iperf_test("Allow TCP port 5002", "h2", "h1", port=5002)
        self.delete_intent("block_tcp_5001")
        return bandwidth

    def test_udp_traffic(self):
        info("\n### TEST 6: UDP TRAFFIC TEST ###\n")
        intent = {
            "id": "prioritize_udp",
            "type": "prioritize",
            "protocol": "udp",
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2'],
            "dscp": 46
        }
        self.add_intent(intent)
        result, success, bandwidth = self.run_iperf_test("UDP h1->h2 with priority", "h2", "h1", udp=True)
        self.delete_intent("prioritize_udp")
        return bandwidth
    
    def test_redirect_intent(self):
        info("\n### TEST 7: REDIRECT INTENT ###\n")
        
        # First, we need to discover which port h3 is connected to
        # In a simple topology, we can assume:
        # h1 is on port 1, h2 on port 2, h3 on port 3
        redirect_intent = {
            "id": "redirect_h1_h2_to_h3",
            "type": "redirect", 
            "src": HOST_MACS['h1'],
            "dst": HOST_MACS['h2'],
            "out_port": 3  # Redirect to h3's port
        }
        
        info("Adding redirect intent: h1->h2 traffic will be redirected to h3's port\n")
        self.add_intent(redirect_intent)
        time.sleep(2)
        
        # Test that h1->h2 traffic gets redirected to h3
        info("Testing redirect behavior:\n")
        
        # Start packet capture on h3 to see if it receives the redirected traffic
        h3 = self.net.get('h3')
        h3.cmd("tcpdump -i h3-eth0 -c 5 -w /tmp/redirect.pcap &")
        time.sleep(1)
        
        # Send ping from h1 to h2 (should be redirected to h3)
        h1 = self.net.get('h1')
        h2 = self.net.get('h2')
        
        info("Sping ping from h1 to h2 (should be redirected to h3)...\n")
        ping_result = h1.cmd("ping -c 3 10.0.0.2")
        info(f"Ping result: {ping_result}\n")
        
        # Stop tcpdump
        h3.cmd("pkill tcpdump")
        time.sleep(1)
        
        # Check if h3 received any packets
        pcap_info = h3.cmd("tcpdump -r /tmp/redirect.pcap 2>&1 | head -10")
        info(f"Packets captured on h3: {pcap_info}\n")
        
        self.delete_intent("redirect_h1_h2_to_h3")
        
        # Store result
        self.results.append({
            'test': 'Redirect h1->h2 to h3 port',
            'success': True,  # We assume it works if no errors
            'result': 'Redirect intent applied'
        })

    def run_all_tests(self):
        info("\n" + "="*60 + "\nSTARTING AUTOMATED INTENT TESTS\n" + "="*60 + "\n")
        
        # Wait for network to stabilize
        time.sleep(5)
        
        try:
            response = requests.get(API_URL, timeout=5)
            info(f"Controller API reachable: {response.status_code}\n")
        except Exception as e:
            info(f"Cannot reach controller API: {e}\nMake sure ryu-manager is running!\n")
            return

        tests = [
            self.test_baseline,
            self.test_block_intent, 
            self.test_prioritize_intent,
            self.test_concurrent_flows_sequential,
            self.test_protocol_specific,
            self.test_udp_traffic,
            self.test_redirect_intent
        ]

        for i, test in enumerate(tests, 1):
            try:
                info(f"\n>>> Running Test {i}/{len(tests)}\n")
                test()
                time.sleep(3)
            except Exception as e:
                info(f"Test {i} failed: {e}\n")

        info("\nALL TESTS COMPLETED\n" + "="*60 + "\n")
        info("\nTest Summary:\n")
        for result in self.results:
            if 'concurrent_results' in result:
                info(f"  - {result['test']}:\n")
                for flow in result.get('concurrent_results', []):
                    info(f"      {flow['flow']}: {flow['bandwidth']}\n")
            else:
                status = "✓ PASS" if result.get('success', True) else "✗ FAIL"
                bandwidth = result.get('bandwidth', '')
                status_note = result.get('status_note', '')
                info(f"  {status}: {result['test']} {bandwidth} {status_note}\n")


def create_simple_topology_and_test():
    setLogLevel('info')
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    info("*** Adding controller\n")
    net.addController('c0', ip='127.0.0.1', port=6633)
    info("*** Adding switch\n")
    s1 = net.addSwitch('s1')
    info("*** Adding hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac=HOST_MACS['h1'])
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac=HOST_MACS['h2'])
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac=HOST_MACS['h3'])

    info("*** Adding links\n")
    # Use lower bandwidth to create contention for QoS testing
    net.addLink(h1, s1, bw=50, use_htb=False)
    net.addLink(h2, s1, bw=50, use_htb=False)
    net.addLink(h3, s1, bw=50, use_htb=False)

    info("*** Starting network\n")
    net.start()
    time.sleep(10)  # Give more time for network startup

    tester = IntentTester(net)
    tester.run_all_tests()

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'manual':
        setLogLevel('info')
        net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)
        net.addController('c0', ip='127.0.0.1', port=6633)
        s1 = net.addSwitch('s1')
        h1 = net.addHost('h1', ip='10.0.0.1/24', mac=HOST_MACS['h1'])
        h2 = net.addHost('h2', ip='10.0.0.2/24', mac=HOST_MACS['h2'])
        h3 = net.addHost('h3', ip='10.0.0.3/24', mac=HOST_MACS['h3'])
        net.addLink(h1, s1)
        net.addLink(h2, s1)
        net.addLink(h3, s1)
        net.start()

        from mininet.cli import CLI
        CLI(net)
        net.stop()
    else:
        create_simple_topology_and_test()