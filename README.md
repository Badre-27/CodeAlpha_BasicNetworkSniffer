
# Basic Network Sniffer
**A Python-based network packet sniffer for real-time traffic analysis.**

This project was developed as **Task 1** of the **CodeAlpha Cybersecurity Internship**. It demonstrates fundamental networking and security concepts by capturing, decoding, and analyzing data packets as they move across a network interface.



## Overview
The Basic Network Sniffer is an educational tool designed to provide insights into network communication. By leveraging the **Scapy** library, it dissects various layers of the OSI model, from Ethernet frames to application-layer protocols like HTTP and DNS.

### Key Features
* **Real-time Capture:** Continuous monitoring of network traffic.
* **Multi-Protocol Analysis:** Supports Ethernet, IP, TCP, UDP, ICMP, and ARP.
* **Traffic Identification:** Automatically detects HTTP (80), HTTPS (443), DNS (53), and ICMP (Ping).
* **Payload Inspection:** Attempts to decode and display the first 50 bytes of raw packet data.
* **Interactive UI:** Menu-driven interface for selecting network adapters and filtering options.


## Getting Started

### Prerequisites
* **Python 3.6+**
* **Scapy Library**
* **Root/Admin Privileges:** Required for raw socket access and packet injection.
* **Npcap (Windows)** or **libpcap (Linux)**

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Badre-27/CodeAlpha_BasicNetworkSniffer
   cd CodeAlpha_BasicNetworkSniffer
   ```
2. **Install dependencies:**
   ```bash
   pip install scapy
   ```

### Usage
> [!IMPORTANT]
> This script must be run with elevated privileges to access the network interface.

**Windows:**
Run your terminal (CMD or PowerShell) as **Administrator**:
```bash
python network-sniffer.py
```

**Linux / macOS:**
```bash
sudo python network-sniffer.py
```

---

## Technical Details

### Information Captured
The sniffer extracts the following specific fields to provide a comprehensive view of network activity:

| Layer | Data Extracted & Analyzed |
| :--- | :--- |
| **Ethernet (L2)** | Source/Destination MAC addresses, Protocol Type (IPv4/ARP). |
| **IP Header (L3)** | Version, Header Length (IHL), Time to Live (TTL), Protocol ID. |
| **Network Layer** | Real-time Source and Destination IP addresses. |
| **TCP Header (L4)** | Source/Destination Ports, Control Flags, Acknowledgment numbers. |
| **UDP Header (L4)** | Source/Destination Ports, total Packet Length. |
| **ARP Protocol** | Opcode (Request/Reply), Sender/Target Hardware and Protocol IPs. |
| **Protocol Detection** | Automated flagging for **HTTP**, **HTTPS**, **DNS**, and **ICMP**. |
| **Payload** | Raw Hex-to-Text decoding attempts (First 50 bytes). |

### Technologies Used
* **Python 3:** Core logic and scripting.
* **Scapy:** High-level packet manipulation and decoding.

---

## Sample Output
```text
PACKET #146
Timestamp: 2026-03-31 07:39:05.279167
Ethernet Frame: Source MAC: d8:42:f7:18:40:0c Destination MAC: a0:d3:c1:2b:1e:51 Protocol: 2048
IP Header: Version: 4 Header Length: 5 TTL: 50 Protocol: 6
Source IP: 149.154.167.91 Destination IP: 192.168.1.164
TCP Header: Source Port: 443 Destination Port: 65505
Flags: PA Acknowledgment: 1409005763
[HTTPS Traffic Detected]
Raw Payload (First 50 bytes): b'\xe2\xd5]\x10\xe4\x9b\tkm\x99\x88\xfc[*\xa84\x06\xe1\xb51\x98\x18\xa1N~P\xf5\x15\x01\xa8x\xdd\xbd\xe1ul\xdc]P\rj\x07\xe6\x9d\x99\xbdY\xc1\xff2'
j杙Y2Decoding Attempt: ]        km[*41N~Pxݽul]P
Packet Size: 1294 bytes

```

---

##  Security considerations
This tool is for **educational purposes only**. 


---

##  Author
**Badreddine Otmane**
* **Role:** Cybersecurity Intern @ CodeAlpha
* **Student ID:** CA/DF1/38745
* **Program:** March 20 – April 20, 2026

## About CodeAlpha
CodeAlpha provides hands-on internship programs to empower students with real-world technical skills.
* **Website:** [www.codealpha.tech](http://www.codealpha.tech)
* **Email:** services@codealpha.tech

---
