#!/usr/bin/env python3
"""
Advanced WiFi Packet Analyzer for Windows
Real-time packet capture and analysis with comprehensive statistics
"""

import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter
import socket
import struct

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Raw, conf
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
except ImportError:
    print("Error: scapy is required. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init
    from tabulate import tabulate
except ImportError:
    print("Error: colorama and tabulate are required. Install with: pip install -r requirements.txt")
    sys.exit(1)

init(autoreset=True)


class WiFiPacketAnalyzer:
    """Main WiFi packet analyzer class"""
    
    def __init__(self, packet_count=0, filter_protocol=None, verbose=False):
        self.packet_count = packet_count
        self.filter_protocol = filter_protocol
        self.verbose = verbose
        self.packets_captured = 0
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'sources': Counter(),
            'destinations': Counter(),
            'mac_addresses': Counter(),
            'ips': Counter(),
            'packet_sizes': [],
            'protocols_detail': defaultdict(int),
            'beacon_frames': [],
            'probe_requests': [],
            'data_frames': [],
            'arp_packets': [],
            'tcp_connections': [],
            'udp_flows': [],
            'icmp_packets': [],
        }
        self.start_time = None
        self.end_time = None
        
    def get_mac_address(self, packet):
        """Extract MAC address from packet"""
        if packet.haslayer(Dot11):
            return packet[Dot11].addr2
        return "N/A"
    
    def get_ip_info(self, packet):
        """Extract IP source and destination"""
        if packet.haslayer(IP):
            return packet[IP].src, packet[IP].dst
        return None, None
    
    def parse_beacon_frame(self, packet):
        """Parse 802.11 Beacon frames"""
        if packet.haslayer(Dot11Beacon):
            try:
                ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore')
                bssid = packet[Dot11].addr3
                channel = None
                if Dot11.haslayer(packet, Dot11):
                    for field in packet[Dot11].notdecoded:
                        if 'Channel' in str(field):
                            channel = field
                
                beacon_info = {
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'ssid': ssid if ssid else "[Hidden Network]",
                    'bssid': bssid,
                    'signal_strength': getattr(packet, 'dBm_AntSignal', 'N/A')
                }
                self.stats['beacon_frames'].append(beacon_info)
                return beacon_info
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing beacon: {e}")
        return None
    
    def parse_probe_request(self, packet):
        """Parse 802.11 Probe Request frames"""
        if packet.haslayer(Dot11ProbeReq):
            try:
                ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore')
                src_mac = packet[Dot11].addr2
                
                probe_info = {
                    'timestamp': datetime.now().strftime("%H:%M:%S"),
                    'source_mac': src_mac,
                    'ssid': ssid if ssid else "[Broadcast Probe]",
                }
                self.stats['probe_requests'].append(probe_info)
                return probe_info
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing probe request: {e}")
        return None
    
    def parse_arp_packet(self, packet):
        """Parse ARP packets"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            arp_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'operation': 'Request' if arp.op == 1 else 'Reply',
                'src_ip': arp.psrc,
                'src_mac': arp.hwsrc,
                'dst_ip': arp.pdst,
                'dst_mac': arp.hwdst,
            }
            self.stats['arp_packets'].append(arp_info)
            return arp_info
        return None
    
    def parse_tcp_packet(self, packet):
        """Parse TCP packets"""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_ip, dst_ip = self.get_ip_info(packet)
            
            tcp_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'src_ip': src_ip,
                'src_port': tcp.sport,
                'dst_ip': dst_ip,
                'dst_port': tcp.dport,
                'flags': tcp.flags,
                'seq': tcp.seq,
                'ack': tcp.ack,
            }
            self.stats['tcp_connections'].append(tcp_info)
            return tcp_info
        return None
    
    def parse_udp_packet(self, packet):
        """Parse UDP packets"""
        if packet.haslayer(UDP):
            udp = packet[UDP]
            src_ip, dst_ip = self.get_ip_info(packet)
            
            udp_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'src_ip': src_ip,
                'src_port': udp.sport,
                'dst_ip': dst_ip,
                'dst_port': udp.dport,
                'length': udp.len,
            }
            self.stats['udp_flows'].append(udp_info)
            return udp_info
        return None
    
    def parse_icmp_packet(self, packet):
        """Parse ICMP packets"""
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            src_ip, dst_ip = self.get_ip_info(packet)
            
            icmp_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'type': icmp.type,
                'code': icmp.code,
            }
            self.stats['icmp_packets'].append(icmp_info)
            return icmp_info
        return None
    
    def get_protocol_name(self, packet):
        """Determine the protocol name from packet"""
        if packet.haslayer(Dot11Beacon):
            return "802.11 Beacon"
        elif packet.haslayer(Dot11ProbeReq):
            return "802.11 Probe Request"
        elif packet.haslayer(Dot11ProbeResp):
            return "802.11 Probe Response"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            return "Other"
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        self.packets_captured += 1
        self.stats['total_packets'] += 1
        
        protocol = self.get_protocol_name(packet)
        self.stats['protocols'][protocol] += 1
        self.stats['protocols_detail'][protocol] += 1
        
        # Filter packets if specified
        if self.filter_protocol and protocol.lower() != self.filter_protocol.lower():
            return
        
        # Get packet size
        packet_size = len(packet)
        self.stats['packet_sizes'].append(packet_size)
        
        # Extract MAC addresses
        mac = self.get_mac_address(packet)
        if mac != "N/A":
            self.stats['mac_addresses'][mac] += 1
        
        # Extract IP addresses
        src_ip, dst_ip = self.get_ip_info(packet)
        if src_ip:
            self.stats['sources'][src_ip] += 1
            self.stats['ips'][src_ip] += 1
        if dst_ip:
            self.stats['destinations'][dst_ip] += 1
            self.stats['ips'][dst_ip] += 1
        
        # Parse specific packet types
        if protocol == "802.11 Beacon":
            self.parse_beacon_frame(packet)
        elif protocol == "802.11 Probe Request":
            self.parse_probe_request(packet)
        elif protocol == "ARP":
            self.parse_arp_packet(packet)
        elif protocol == "TCP":
            self.parse_tcp_packet(packet)
        elif protocol == "UDP":
            self.parse_udp_packet(packet)
        elif protocol == "ICMP":
            self.parse_icmp_packet(packet)
        
        # Print packet info in verbose mode
        if self.verbose:
            self.print_packet_info(packet, protocol)
    
    def print_packet_info(self, packet, protocol):
        """Print detailed packet information"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        size = len(packet)
        src_ip, dst_ip = self.get_ip_info(packet)
        
        info = f"{Fore.CYAN}[{timestamp}]{Style.RESET_ALL} "
        info += f"{Fore.GREEN}#{self.packets_captured}{Style.RESET_ALL} "
        info += f"Protocol: {Fore.YELLOW}{protocol}{Style.RESET_ALL} "
        info += f"Size: {Fore.MAGENTA}{size} bytes{Style.RESET_ALL}"
        
        if src_ip and dst_ip:
            info += f" | {Fore.BLUE}{src_ip} → {dst_ip}{Style.RESET_ALL}"
        
        print(info)
    
    def display_statistics(self):
        """Display comprehensive statistics"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"WiFi PACKET ANALYZER STATISTICS")
        print(f"{'='*80}{Style.RESET_ALL}\n")
        
        # Overall Statistics
        print(f"{Fore.GREEN}[OVERALL STATISTICS]{Style.RESET_ALL}")
        print(f"Total Packets Captured: {Fore.YELLOW}{self.stats['total_packets']}{Style.RESET_ALL}")
        print(f"Capture Duration: {self.end_time - self.start_time if self.end_time and self.start_time else 'N/A'}")
        
        if self.stats['packet_sizes']:
            avg_size = sum(self.stats['packet_sizes']) / len(self.stats['packet_sizes'])
            print(f"Average Packet Size: {Fore.YELLOW}{avg_size:.2f} bytes{Style.RESET_ALL}")
            print(f"Min/Max Packet Size: {Fore.YELLOW}{min(self.stats['packet_sizes'])}/{max(self.stats['packet_sizes'])} bytes{Style.RESET_ALL}")
        
        # Protocol Distribution
        print(f"\n{Fore.GREEN}[PROTOCOL DISTRIBUTION]{Style.RESET_ALL}")
        if self.stats['protocols']:
            protocol_data = [[proto, count, f"{(count/self.stats['total_packets']*100):.1f}%"] 
                           for proto, count in self.stats['protocols'].most_common(10)]
            print(tabulate(protocol_data, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
        
        # Top Source IPs
        if self.stats['sources']:
            print(f"\n{Fore.GREEN}[TOP SOURCE IPs]{Style.RESET_ALL}")
            source_data = [[ip, count] for ip, count in self.stats['sources'].most_common(10)]
            print(tabulate(source_data, headers=["Source IP", "Count"], tablefmt="grid"))
        
        # Top Destination IPs
        if self.stats['destinations']:
            print(f"\n{Fore.GREEN}[TOP DESTINATION IPs]{Style.RESET_ALL}")
            dest_data = [[ip, count] for ip, count in self.stats['destinations'].most_common(10)]
            print(tabulate(dest_data, headers=["Destination IP", "Count"], tablefmt="grid"))
        
        # Beacon Frames
        if self.stats['beacon_frames']:
            print(f"\n{Fore.GREEN}[802.11 BEACON FRAMES]{Style.RESET_ALL}")
            beacon_data = [[b['timestamp'], b['ssid'], b['bssid'], b['signal_strength']] 
                         for b in self.stats['beacon_frames'][:10]]
            print(tabulate(beacon_data, headers=["Time", "SSID", "BSSID", "Signal"], tablefmt="grid"))
        
        # Probe Requests
        if self.stats['probe_requests']:
            print(f"\n{Fore.GREEN}[PROBE REQUESTS]{Style.RESET_ALL}")
            probe_data = [[p['timestamp'], p['source_mac'], p['ssid']] 
                        for p in self.stats['probe_requests'][:10]]
            print(tabulate(probe_data, headers=["Time", "Source MAC", "SSID"], tablefmt="grid"))
        
        # ARP Packets
        if self.stats['arp_packets']:
            print(f"\n{Fore.GREEN}[ARP PACKETS]{Style.RESET_ALL}")
            arp_data = [[a['timestamp'], a['operation'], a['src_ip'], a['src_mac'], a['dst_ip']] 
                       for a in self.stats['arp_packets'][:10]]
            print(tabulate(arp_data, headers=["Time", "Op", "Src IP", "Src MAC", "Dst IP"], tablefmt="grid"))
        
        # TCP Connections
        if self.stats['tcp_connections']:
            print(f"\n{Fore.GREEN}[TCP CONNECTIONS]{Style.RESET_ALL}")
            tcp_data = [[t['timestamp'], t['src_ip'], t['src_port'], t['dst_ip'], t['dst_port']] 
                       for t in self.stats['tcp_connections'][:10]]
            print(tabulate(tcp_data, headers=["Time", "Src IP", "Sport", "Dst IP", "Dport"], tablefmt="grid"))
        
        # UDP Flows
        if self.stats['udp_flows']:
            print(f"\n{Fore.GREEN}[UDP FLOWS]{Style.RESET_ALL}")
            udp_data = [[u['timestamp'], u['src_ip'], u['src_port'], u['dst_ip'], u['dst_port'], u['length']] 
                       for u in self.stats['udp_flows'][:10]]
            print(tabulate(udp_data, headers=["Time", "Src IP", "Sport", "Dst IP", "Dport", "Len"], tablefmt="grid"))
        
        # ICMP Packets
        if self.stats['icmp_packets']:
            print(f"\n{Fore.GREEN}[ICMP PACKETS]{Style.RESET_ALL}")
            icmp_data = [[i['timestamp'], i['src_ip'], i['dst_ip'], i['type'], i['code']] 
                        for i in self.stats['icmp_packets'][:10]]
            print(tabulate(icmp_data, headers=["Time", "Src IP", "Dst IP", "Type", "Code"], tablefmt="grid"))
        
        # Top MAC Addresses
        if self.stats['mac_addresses']:
            print(f"\n{Fore.GREEN}[TOP MAC ADDRESSES]{Style.RESET_ALL}")
            mac_data = [[mac, count] for mac, count in self.stats['mac_addresses'].most_common(10)]
            print(tabulate(mac_data, headers=["MAC Address", "Count"], tablefmt="grid"))
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    def start_capture(self, interface=None):
        """Start packet capture"""
        print(f"{Fore.GREEN}[+] Starting WiFi Packet Analyzer...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop capture{Style.RESET_ALL}\n")
        
        self.start_time = datetime.now()
        
        try:
            # Use the specified interface or let scapy auto-detect
            if interface:
                print(f"{Fore.YELLOW}[*] Using interface: {interface}{Style.RESET_ALL}")
                sniff(prn=self.packet_callback, iface=interface, 
                      store=False, count=self.packet_count if self.packet_count > 0 else 0)
            else:
                print(f"{Fore.YELLOW}[*] Auto-detecting interface...{Style.RESET_ALL}\n")
                sniff(prn=self.packet_callback, 
                      store=False, count=self.packet_count if self.packet_count > 0 else 0)
        
        except KeyboardInterrupt:
            print(f"\n\n{Fore.RED}[!] Capture interrupted by user{Style.RESET_ALL}")
        except PermissionError:
            print(f"{Fore.RED}[!] Error: This program requires administrator privileges!{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Please run as Administrator (Windows) or use 'sudo' (Linux/Mac){Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error during capture: {e}{Style.RESET_ALL}")
            sys.exit(1)
        finally:
            self.end_time = datetime.now()
            self.display_statistics()


def list_interfaces():
    """List all available network interfaces"""
    try:
        from scapy.arch import get_windows_if_list
        interfaces = get_windows_if_list()
        print(f"\n{Fore.GREEN}[*] Available Network Interfaces:{Style.RESET_ALL}\n")
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {Fore.CYAN}{iface.get('name', 'Unknown')}{Style.RESET_ALL} - {iface.get('description', 'No description')}")
            print(f"   IP: {iface.get('ipv4_list', ['N/A'])[0] if iface.get('ipv4_list') else 'N/A'}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error listing interfaces: {e}{Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced WiFi Packet Analyzer for Windows',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wifi_analyzer.py                    # Start capture on default interface
  python wifi_analyzer.py -i "Ethernet"      # Capture on specific interface
  python wifi_analyzer.py -c 100             # Capture 100 packets
  python wifi_analyzer.py -p TCP             # Capture only TCP packets
  python wifi_analyzer.py --list-interfaces  # List available interfaces
  python wifi_analyzer.py -v -i "WiFi"       # Verbose mode on WiFi interface
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-p', '--protocol', help='Filter by protocol (TCP, UDP, ARP, ICMP, etc.)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (print each packet)')
    parser.add_argument('--list-interfaces', action='store_true', help='List available network interfaces')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    analyzer = WiFiPacketAnalyzer(
        packet_count=args.count,
        filter_protocol=args.protocol,
        verbose=args.verbose
    )
    
    analyzer.start_capture(interface=args.interface)


if __name__ == '__main__':
    main()
