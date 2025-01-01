from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter
from collections import defaultdict
import time


def findIpAndMac(packets):
    ipMacMapping=Counter()
    for packet in packets:
        if packet.haslayer('IP') and packet.haslayer('Ether'):
            ipMacMapping[packet['IP'].src]=packet['Ether'].src
    return ipMacMapping  
        
        
def loadPcap(fileName):
    # Load the PCAP file
    packets = rdpcap(fileName)
    # Inspect packets
    return packets

def detectNSP(packets):
    nspIPs=set()
    # Non-standard ports detection
    for packet in packets:
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            if tcp_layer.dport not in [80, 443, 22]:  # Standard ports (HTTP, HTTPS, SSH)
                if packet.haslayer('IP'):
                     nspIPs.add(packet['IP'].src)
    return nspIPs

def detectDDOS(packets):
    ip_count = Counter()
    threshold = 100  # Set your threshold
    ddos_candidates=set()
    for packet in packets:
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            ip_count[ip_layer.src] += 1
    for ip, count in ip_count.items():
        if count > threshold:
            ddos_candidates.add(ip)
    return ddos_candidates

def checkSize(packets):
    MAX_MTU = 1500  # Maximum Transmission Unit (MTU)
    exceedingPackets = set()
    for packet in packets:
        size = len(packet)
        if size > MAX_MTU:  # MTU size exceeds standard Ethernet
            if packet.haslayer('IP'):
                ip_layer = packet['IP']
                exceedingPackets.add(ip_layer.src)
    return exceedingPackets

def detectSynFlood(packets):
    SYN_FLOOD_THRESHOLD = 100 # Number of SYN packets in a short period
    syn_count = defaultdict(int)
    flooding_ip = set()
    for packet in packets:
        if packet.haslayer(TCP) and packet['TCP'].flags == 0x02:  # SYN flag set
            src_ip = packet['IP'].src
            syn_count[src_ip] += 1
    for ip, count in syn_count.items():
        if count > SYN_FLOOD_THRESHOLD:
            flooding_ip.add(ip)
    return flooding_ip
def portScanning(packets):
    PORT_SCAN_THRESHOLD = 5 # Connection attempts on multiple ports from the same IP
    connection_attempts = defaultdict(set) # Source IP -> Set of destination ports
    scanningMultiplePorts=set()
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet['TCP']
            if packet.haslayer(IP):
                connection_attempts[packet[IP].src].add(tcp_layer.dport)
    for ip, ports in connection_attempts.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            scanningMultiplePorts.add(ip)
    return scanningMultiplePorts
    
def detectUnsolicitedARP(packets):
    arp_requests = set()  # Set to track IPs that have sent ARP requests
    arp_replies = set()   # Set to track IPs that have sent ARP replies
    unsolicited_replies = set()  # Set to track unsolicited ARP reply IPs

    for packet in packets:
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            if arp_layer.op == 1:  # ARP request (op == 1)
                arp_requests.add(arp_layer.psrc)  # Track source IP of ARP request
            elif arp_layer.op == 2:  # ARP reply (op == 2)
                if arp_layer.psrc not in arp_requests:  # No prior ARP request for this IP
                    unsolicited_replies.add(arp_layer.psrc)  # It's an unsolicited reply
                arp_replies.add(arp_layer.psrc)  # Track source IP of ARP reply

    return unsolicited_replies

 
    
def detectLargeDNSResponses(packets, size_threshold=512):
    large_dns_responses = []

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(IP):
            dns_layer = packet[DNS]
            if dns_layer.qr == 1:  # It's a DNS response
                if len(packet) > size_threshold:  # Check if DNS response is larger than the threshold
                    large_dns_responses.append(packet)

    return large_dns_responses
    
def detectExcessiveICMPEcho(packets, threshold=100, time_window=60):
    icmp_requests = defaultdict(list)  # Stores timestamps of ICMP Echo requests per IP
    excessive_icmp = []

    # Iterate through packets and track ICMP Echo requests
    for packet in packets:
        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            if icmp_layer.type == 8:  # ICMP Echo request (ping)
                src_ip = packet[IP].src
                timestamp = packet.time  # Timestamp of the packet
                
                # Append the timestamp of the ICMP Echo request for this source IP
                icmp_requests[src_ip].append(timestamp)
                
                # Remove timestamps that are outside the time window
                icmp_requests[src_ip] = [t for t in icmp_requests[src_ip] if timestamp - t <= time_window]

                # Check if the number of requests exceeds the threshold within the time window
                if len(icmp_requests[src_ip]) > threshold:
                    if src_ip not in excessive_icmp:
                        excessive_icmp.append(src_ip)

    return excessive_icmp

