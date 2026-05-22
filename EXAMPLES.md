# WiFi Packet Analyzer - Usage Examples

This document provides detailed examples of how to use the WiFi Packet Analyzer for various scenarios.

## Table of Contents
1. [Basic Usage](#basic-usage)
2. [Protocol-Specific Capture](#protocol-specific-capture)
3. [Network Monitoring](#network-monitoring)
4. [Security Analysis](#security-analysis)
5. [Troubleshooting](#troubleshooting)
6. [Advanced Scenarios](#advanced-scenarios)

---

## Basic Usage

### Example 1: Quick Packet Capture (Default Interface)
Capture packets on the default network interface with automatic statistics.

```bash
python wifi_analyzer.py
```

**Output:**
```
[+] Starting WiFi Packet Analyzer...
[*] Press Ctrl+C to stop capture
[*] Auto-detecting interface...

# Packets will be displayed as they're captured
# Press Ctrl+C when done
```

**Use Case:** Quick network traffic overview, immediate diagnostics

---

### Example 2: List Available Interfaces
Before capturing, view all available network adapters.

```bash
python wifi_analyzer.py --list-interfaces
```

**Output:**
```
[*] Available Network Interfaces:

1. Ethernet - Intel(R) Ethernet Connection (2) I219-V
   IP: 192.168.1.100
2. WiFi - Qualcomm Atheros AR9485 Wireless Network Adapter
   IP: 192.168.1.101
3. Bluetooth Network Connection - Bluetooth Network Connection
   IP: N/A
```

**Use Case:** Identify correct interface before capturing

---

### Example 3: Capture on Specific Interface
Target a specific network adapter.

```bash
python wifi_analyzer.py -i "WiFi"
```

or

```bash
python wifi_analyzer.py -i "Ethernet"
```

**Use Case:** Monitor specific network (WiFi vs Ethernet), isolate noisy interfaces

---

## Protocol-Specific Capture

### Example 4: Monitor TCP Traffic Only
Focus on TCP connections and data transfer.

```bash
python wifi_analyzer.py -p TCP
```

**Statistics Output:**
```
[PROTOCOL DISTRIBUTION]
TCP                     1,200    100.0%

[TOP SOURCE IPs]
192.168.1.5             450
192.168.1.10            320
10.0.0.15               200

[TCP CONNECTIONS]
Time     | Src IP      | Sport | Dst IP     | Dport
---------|-------------|-------|------------|-------
14:23:45 | 192.168.1.5 | 54321 | 8.8.8.8    | 443
14:23:46 | 192.168.1.5 | 54322 | 93.184.216 | 80
```

**Use Case:** Monitor web browsing, file transfers, secure connections (HTTPS)

---

### Example 5: Monitor UDP Traffic
Track UDP flows and services.

```bash
python wifi_analyzer.py -p UDP
```

**Statistics Output:**
```
[UDP FLOWS]
Time     | Src IP      | Sport | Dst IP     | Dport | Len
---------|-------------|-------|------------|-------|-----
14:23:45 | 192.168.1.1 | 53    | 192.168.1. | 54321 | 512
14:23:46 | 192.168.1.5 | 5353  | 224.0.0.25 | 5353  | 180
```

**Use Case:** Monitor DNS queries, DHCP, mDNS, gaming traffic

---

### Example 6: Monitor ARP Traffic
Track ARP requests and replies for network mapping.

```bash
python wifi_analyzer.py -p ARP
```

**Statistics Output:**
```
[ARP PACKETS]
Time     | Op    | Src IP      | Src MAC           | Dst IP
---------|-------|-------------|-------------------|----------
14:23:45 | Req   | 192.168.1.5 | AA:BB:CC:DD:EE:FF | 192.168.1.1
14:23:46 | Reply | 192.168.1.1 | 00:11:22:33:44:55 | 192.168.1.5
```

**Use Case:** Network enumeration, ARP spoofing detection, device discovery

---

### Example 7: Monitor ICMP (Ping)
Track ICMP ping and error messages.

```bash
python wifi_analyzer.py -p ICMP
```

**Statistics Output:**
```
[ICMP PACKETS]
Time     | Src IP      | Dst IP      | Type | Code
---------|-------------|-------------|------|-----
14:23:45 | 192.168.1.5 | 8.8.8.8     | 8    | 0     (Echo Request)
14:23:46 | 8.8.8.8     | 192.168.1.5 | 0    | 0     (Echo Reply)
```

**Use Case:** Ping monitoring, network connectivity diagnosis

---

### Example 8: Monitor WiFi Beacon Frames
Capture WiFi network advertisements.

```bash
python wifi_analyzer.py -p "802.11 Beacon"
```

**Statistics Output:**
```
[802.11 BEACON FRAMES]
Time     | SSID              | BSSID              | Signal
---------|-------------------|--------------------|---------
14:23:45 | MyNetworkSSID     | AA:BB:CC:DD:EE:01  | -42dBm
14:23:50 | GuestNetwork      | AA:BB:CC:DD:EE:02  | -58dBm
14:23:55 | [Hidden Network]  | AA:BB:CC:DD:EE:03  | -65dBm
```

**Use Case:** Network discovery, hidden SSID detection, AP enumeration

---

## Network Monitoring

### Example 9: Capture Limited Number of Packets
Capture exactly 100 packets and generate report.

```bash
python wifi_analyzer.py -c 100
```

**Use Case:** Quick baseline measurement, performance testing, avoid large datasets

---

### Example 10: Long-Duration Monitoring
Capture for extended period (no count limit, Ctrl+C to stop).

```bash
python wifi_analyzer.py
```

**Duration:** Run until manually interrupted
**Use Case:** Network health monitoring, trend analysis, anomaly detection

---

### Example 11: Verbose Mode with Limited Packets
See each packet as it's captured.

```bash
python wifi_analyzer.py -v -c 50
```

**Output:**
```
[14:23:45.123] #1 Protocol: TCP Size: 1514 bytes | 192.168.1.5 → 8.8.8.8
[14:23:45.234] #2 Protocol: UDP Size: 512 bytes | 192.168.1.1 → 8.8.4.4
[14:23:45.345] #3 Protocol: ARP Size: 64 bytes | 192.168.1.100 → 192.168.1.1
[14:23:45.456] #4 Protocol: 802.11 Beacon Size: 156 bytes
[14:23:45.567] #5 Protocol: ICMP Size: 98 bytes | 192.168.1.5 → 192.168.1.1
...
```

**Use Case:** Packet-by-packet inspection, debugging, detailed analysis

---

## Security Analysis

### Example 12: Detect WiFi Network Enumeration
Monitor for probe requests (devices searching for networks).

```bash
python wifi_analyzer.py -p "802.11 Probe Request" -v
```

**Output:**
```
[14:23:45.123] #1 Protocol: 802.11 Probe Request Size: 64 bytes
[14:23:45.234] #2 Protocol: 802.11 Probe Request Size: 64 bytes

[PROBE REQUESTS]
Time     | Source MAC        | SSID
---------|-------------------|--------------------
14:23:45 | AA:BB:CC:DD:EE:01 | HomeNetwork
14:23:46 | AA:BB:CC:DD:EE:01 | CoffeShop5G
14:23:47 | AA:BB:CC:DD:EE:01 | [Broadcast Probe]
```

**Use Case:** Identify devices searching for networks, privacy analysis

---

### Example 13: Monitor for ARP Spoofing
Detect suspicious ARP activity indicating potential spoofing attacks.

```bash
python wifi_analyzer.py -p ARP -v -i "Ethernet"
```

**Analysis Tips:**
- Look for multiple replies to same IP (ARP poisoning)
- Monitor unusual MAC-to-IP mappings
- Track rapid ARP requests

**Use Case:** Network security, attack detection, MITM prevention

---

### Example 14: Monitor Suspicious Port Activity
Identify unusual outbound connections on uncommon ports.

```bash
python wifi_analyzer.py -p TCP -v -c 1000
```

**Look For:**
- Connections to unusual destinations (not known services)
- Multiple failed connection attempts
- Connections on non-standard ports (e.g., 22, 3389 from expected IPs)

**Use Case:** Intrusion detection, malware activity monitoring

---

## Troubleshooting

### Example 15: Verify Setup Works (Limited Scope)
Test the analyzer on localhost before network monitoring.

```bash
python wifi_analyzer.py -i "Ethernet" -c 10 -v
```

**Expected Output:** 
- Should capture some packets
- Should list interfaces without errors
- Should complete successfully

**Diagnostic Steps:**
```bash
# 1. Verify Python installation
python --version

# 2. List interfaces
python wifi_analyzer.py --list-interfaces

# 3. Test with Ethernet first
python wifi_analyzer.py -i "Ethernet" -c 5

# 4. Check Npcap installation
# In Windows: Settings > Apps > Apps & features > Search "Npcap"
```

---

### Example 16: Identify Network Bottlenecks
Monitor to find high-traffic IPs/protocols.

```bash
python wifi_analyzer.py -c 5000
```

**Analysis Steps:**
1. Review "PROTOCOL DISTRIBUTION" - which protocol uses most bandwidth?
2. Check "TOP SOURCE IPs" - which device generates most traffic?
3. Check "TOP DESTINATION IPs" - where is traffic going?
4. Review "Average Packet Size" - large packets indicate bulk data transfer

---

## Advanced Scenarios

### Example 17: Monitor Specific Application Traffic
Monitor traffic on WiFi interface with verbose output.

```bash
python wifi_analyzer.py -i "WiFi" -v -p TCP -c 500
```

**Steps:**
1. Run command before starting application
2. Launch your target application
3. Interact with application normally
4. Press Ctrl+C to stop capture
5. Analyze captured TCP connections to see communication patterns

**Use Case:** Understanding app network behavior, API debugging

---

### Example 18: Network Baseline Establishment
Create a baseline of normal network activity.

```bash
python wifi_analyzer.py -c 10000
```

**Metrics to Record:**
- Average packets per minute: `total_packets / duration_minutes`
- Protocol distribution percentages
- Top IPs and frequency
- Typical packet size range

**Use Case:** Establish normal baseline, detect anomalies later

---

### Example 19: Compare Traffic Between Interfaces
Monitor both Ethernet and WiFi to identify differences.

```bash
# Terminal 1: Ethernet traffic
python wifi_analyzer.py -i "Ethernet" -c 1000

# Terminal 2: WiFi traffic  
python wifi_analyzer.py -i "WiFi" -c 1000
```

**Compare:**
- Protocol distribution
- Source/destination IPs
- Packet sizes
- Overall traffic volume

**Use Case:** Network diagnostics, interface comparison, optimization

---

### Example 20: Generate Security Report
Comprehensive capture for security analysis.

```bash
python wifi_analyzer.py -v -c 2000
```

**Report Should Include:**
- Total packets and duration
- Protocol breakdown
- Top communicating devices
- ARP activity summary
- Beacon frames and SSIDs found
- Any unusual patterns or high-volume flows

**Use Case:** Network security audit, compliance reporting

---

## Tips & Best Practices

### Performance Optimization
- Use protocol filters (`-p`) to reduce output noise
- Use packet count limits (`-c`) for initial analysis
- Capture on specific interface (`-i`) if bandwidth is limited

### Accurate Analysis
- Run multiple captures to ensure consistency
- Compare baseline with suspected problem period
- Use verbose mode for detailed inspection

### Security Considerations
- Only monitor networks you own/control
- Be aware of packet capture legality in your jurisdiction
- Respect privacy of other network users
- Document your monitoring activities

### Common Issues
| Issue | Solution |
|-------|----------|
| No packets captured | Verify interface with `--list-interfaces`, check admin rights |
| High CPU usage | Reduce packet count or use protocol filter |
| Npcap errors | Uninstall, restart PC, reinstall Npcap |
| Interface name mismatch | Use exact name from `--list-interfaces` |

---

## Conclusion

The WiFi Packet Analyzer is a powerful tool for network analysis, monitoring, and troubleshooting. These examples cover common use cases, but the tool's flexibility allows for many other scenarios. Experiment safely and responsibly!

For more information, see the main [README.md](README.md).
