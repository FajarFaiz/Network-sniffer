<div align="center"> <video src="https://github.com/user-attachments/assets/417214fa-3dc0-4897-910e-02fb347d4a49" width="100%" autoplay loop muted>
  
</video> <p><i>Python Network Sniffer Demo</i></p> </div> 
# Python Network Sniffer 

A lightweight, cross-platform network packet sniffer written in Python using the Scapy engine. This tool captures, unpacks, and analyzes live network traffic, breaking down packets into readable data structures across the IPv4, TCP, UDP, and ICMP protocols.

##  Features
- **Live Traffic Monitoring**: Intercepts real-time incoming and outgoing packets.
- **Protocol Identification**: Automatically separates and parses different network headers.
- **Deep Inspection**: Extracts version, TTL, Source/Destination IPs, Ports, and Sequences.
- **Payload Hex View**: Formats raw payload blocks cleanly to inspect unencrypted content safely.

## 🛠️ Requirements & Installation
This project requires administrative rights to tap into system network cards.

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd python-network-sniffer
   ```

2. **Install dependencies:**
   ```bash
   pip install scapy
   ```






##  Usage Instructions

### Windows Users
You must launch your console with elevated user privileges:
1. Open PowerShell or Command Prompt as **Administrator**.
2. Run the script:
   ```cmd
   python sniffer_demo.py
   ```

### Linux Users
Raw packet listening requires root access permissions:
```bash
sudo python3 sniffer_demo.py
```

##  Example Output
```text
[*] IPv4 Packet Captured:
     - Version: 4, Header Length: 20 bytes
     - TTL: 64, Protocol: 6
     - Source IP: 192.168.1.15 -> Destination IP: 93.184.216.34
         - TCP Segment:
             - Source Port: 53214, Destination Port: 80
             - Sequence Number: 1042394, Acknowledgment: 0
             - Data Payload:
                 \x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a
```

## ⚠️ Disclaimer
This tool is built solely for educational projects and authorized security analysis. Monitoring network devices you do not own or lack express permission to audit is strictly prohibited.
