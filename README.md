# PacketPulse - Deep Packet Analyzer & Intrusion Detection System

**PacketPulse** is a full-featured, visually stunning web-based Deep Packet Inspection (DPI) tool and Network Intrusion Detection System (IDS) built with **Python, Flask, and Scapy** on the backend, and a modern **Vanilla CSS/JS** cyberpunk dashboard on the frontend. 

It captures live network traffic on selected interfaces, dissects layers down to raw byte offsets, evaluates traffic against threat signatures, and presents insights in real-time.

---

## 🌟 Key Features

* **Real-time Live Packet Capturing**: Sniff packets on active network adapters or internal loopback interfaces.
* **Deep Protocol Dissection**: Fully decodes protocol layers:
  * **Link Layer**: Ethernet, ARP
  * **Network Layer**: IPv4, IPv6
  * **Transport Layer**: TCP (including flag summaries), UDP, ICMP, ICMPv6
  * **Application Layer**: DNS, HTTP, TLS
* **Encrypted SNI (Server Name Indication) Decoder**: Inspects secure TLS Client Hello handshake packets (port 443) to identify the domain name being visited (e.g. `google.com`) before encryption takes effect.
* **Intrusion Detection System (IDS) Engine**: Scans incoming packets against threat signatures:
  * *Cleartext Credentials Exposure*: Identifies passwords, logins, or authorization headers transmitted in plaintext.
  * *Port Scan Detection*: Triggers alerts when a host hits 10+ different destination ports within 10 seconds.
  * *SYN Flood / DoS Alerting*: Tracks hosts sending >30 SYN packets within 5 seconds.
* **Asynchronous Hostname Resolution Cache**: A background thread pool resolves IP addresses to hostnames (via Reverse DNS lookups) without stalling the live capture loop.
* **Interactive Hex / ASCII Dump**: A side-by-side hexadecimal and ASCII pane. Hovering over a hex byte highlights its corresponding text character and vice versa.
* **Advanced Decoded Payload tab**: Dissects application structures into responsive elements (HTTP headers/parameters grids, DNS Resource Record tables, pretty syntax-colored JSON trees).
* **PCAP Export**: Save the live captured session directly into a standard Wireshark-compatible `.pcap` file.
* **Capture Filters (BPF)**: Use standard BPF syntax (e.g., `tcp and port 80`, `icmp`, `udp`) to filter captured packets at the socket level.

---

## 🛠️ Architecture & Tech Stack

```
                     ┌─────────────────────────────────────────┐
                     │           PacketPulse Web UI            │
                     │  (HTML5 / CSS3 Cyberpunk / ES6 JS)      │
                     └────────────────────┬────────────────────┘
                                          │ HTTP Polling & JSON API
                     ┌────────────────────▼────────────────────┐
                     │          Flask Backend Server           │
                     └────────────────────┬────────────────────┘
                                          │ Multi-threaded Operations
                     ┌────────────────────▼────────────────────┐
                     │        Asynchronous Sniff Thread        │
                     │          (Scapy Capturing Loop)         │
                     └────────────────────┬────────────────────┘
                                          │ Socket Binding
                     ┌────────────────────▼────────────────────┐
                     │    OS Kernel (Npcap/WinPcap Driver)     │
                     └─────────────────────────────────────────┘
```

* **Backend**: Python 3, Flask, Scapy
* **Frontend**: HTML5, Vanilla CSS3 (Custom Glassmorphism layout), Vanilla ES6 JavaScript (Canvas, SVGs, custom JSON highlight parser).
* **Network Driver**: Npcap (Windows) or libpcap (Linux/macOS)

---

## ⚙️ Prerequisites

1. **Python 3.8+** must be installed.
2. **Network Driver**:
   * **Windows**: Install [Npcap](https://npcap.com/) (ensure "Install Npcap in WinPcap API-compatible Mode" is checked).
   * **Linux/macOS**: `libpcap` is usually pre-installed, or can be installed via package managers (`sudo apt-get install libpcap-dev`).
3. **Admin Privileges**: Raw socket sniffing requires running the command prompt or terminal as **Administrator** or **sudo**.

---

## 🚀 Getting Started

### 1. Install Dependencies
Run pip to install the required Python libraries:
```bash
pip install flask scapy
```

### 2. Start the Server
Open an elevated (Administrator) command prompt and navigate to the project directory:
```cmd
cd e:\packet\packet
python app.py
```

### 3. Open the Interface
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📡 REST API Documentation

PacketPulse exposes a set of JSON endpoints to drive the packet sniffer programmatically:

| Method | Endpoint | Description | Request Body / Parameters |
| :--- | :--- | :--- | :--- |
| **GET** | `/` | Serves the main UI Dashboard. | None |
| **GET** | `/api/interfaces` | Returns a list of active network interface adapters. | None |
| **GET** | `/api/status` | Retrieves the current sniffing state. | None |
| **POST** | `/api/start` | Spawns background threads to start packet capture. | `{"interface": "Wi-Fi", "filter": "tcp"}` |
| **POST** | `/api/stop` | Halts the active packet sniffing thread. | None |
| **GET** | `/api/packets` | Returns newly captured packets, metrics, and security alerts. | Optional query: `?after=<packet_id>` |
| **GET** | `/api/packet/<id>` | Fetches deep dissection layers and decoded payload fields. | None |
| **GET** | `/api/export` | Downloads the current capture buffer as a `.pcap` file. | None |

---

## 🎨 Layout Organization

The interface is structured to maximize details on a single screen:
* **Sidebar**: Hosts the live metrics widgets (total packets, capture rate, and bandwidth), protocol distribution bars, and tabbed IP Talkers tables (Top Sources vs. Top Destinations).
* **Header Controls**: Quick selectors for interface binding and BPF filters, alongside Start, Stop, and PCAP Export triggers.
* **IDS Security Console**: A glowing red collapsible bar. If port scanning or cleartext credentials are flagged, it rings the console. Clicking "Locate Packet" jumps directly to the packet in the feed table.
* **Workspace Pane**:
  * **Traffic Feed (Top)**: Real-time table sorting incoming packets with color-coded protocol badges (TCP, UDP, DNS, ICMP, ARP). Supports regular expression search.
  * **Deep Inspector (Bottom)**: Wireshark-style tab panel for inspecting selected packet dissection layers, coordinated hex hover mappings, and parsed payloads.

---