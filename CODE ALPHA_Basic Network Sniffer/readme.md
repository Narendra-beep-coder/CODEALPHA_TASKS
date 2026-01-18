# Network Packet Sniffer with GUI

A Python-based **Network Packet Sniffer** with an interactive GUI for live packet capture, analysis, and export on Kali Linux and WSL (Windows Subsystem for Linux).  
Developed as a security and networking project under **CODE ALPHA** by **Narendra Borhade (Student ID: CA/DF1/6646)**.

## Features

- 🔍 **Live Packet Capture**
  - Captures packets from a selected network interface using `tcpdump`.
  - Supports Ethernet and IP traffic (TCP, UDP, ICMP, ARP).
  - Works on Kali Linux and WSL (for IP-level traffic via `eth0`).

- 📊 **Real-Time Statistics**
  - Total packets captured.
  - Protocol distribution (TCP, UDP, ICMP, ARP, others).
  - Top source/destination IP addresses.
  - Top ports (e.g., HTTP, HTTPS, DNS, SSH).

- 🧩 **Protocol & Application Classification**
  - Decodes Ethernet + IPv4 headers.
  - Identifies transport-layer protocols: TCP, UDP, ICMP.
  - Maps common ports to application types:
    - HTTP/HTTPS, DNS, SSH, SMTP, FTP, POP3, IMAP, DHCP, etc.

- 🖥️ **Interactive GUI (Tkinter)**
  - Interface selection dropdown.
  - Start / Stop / Clear capture controls.
  - Live packet table with time, source, destination, protocol, type, length.
  - Detailed per-packet view (headers, ports, payload preview).
  - Hex view of raw packet bytes.

- 💾 **Data Export**
  - Export captured packets to **JSON**.
  - Export captured packets to **CSV** for Excel / BI tools / custom analysis.

- 🧪 **Educational Focus**
  - Clean, readable Python code for learning network packet structures.
  - Demonstrates binary parsing with `struct`, use of `tcpdump`, and GUI programming.

## Architecture Overview

The application follows a simple three-layer architecture inspired by existing packet-sniffer designs.[web:81]

1. **Capture Layer – `NetworkSniffer`**
   - Spawns `tcpdump` via `subprocess` with:

     ```bash
     tcpdump -i <interface> -n -U -w -
     ```

   - Reads the global pcap header once, then per-packet headers and packet data.
   - Feeds raw packet bytes to the analyzer in a background thread.

2. **Analysis Layer – `PacketAnalyzer` & `NetworkPacket`**
   - Parses:
     - Ethernet header (MAC addresses, EtherType).
     - IPv4 header (source/destination IP, protocol, header length).
     - TCP header (source/destination ports, data offset).
     - UDP header (ports).
     - ICMP header (type, code).
     - ARP frames (via EtherType).
   - Creates `NetworkPacket` objects with:
     - Timestamp, IPs, ports, protocol, inferred application type, payload snippet, raw bytes, MAC addresses.
   - Maintains statistics:
     - Total packet count.
     - Protocol counts.
     - Top IPs and ports (via `collections.Counter`).

3. **Presentation Layer – `NetworkSnifferUI` (Tkinter)**
   - Provides:
     - Control Panel (interface selection, start/stop, clear, export).
     - Packet table (`ttk.Treeview`) for live capture.
     - Details pane for selected packet (headers & payload).
     - Hex view pane for raw byte-level inspection.
     - Statistics pane (labels for counts and top talkers).
   - Uses `root.after` to update GUI safely from capture threads.

## Technology Stack

- **Language:** Python 3.x
- **Libraries:**
  - Standard: `socket`, `struct`, `binascii`, `subprocess`, `csv`, `json`, `collections`, `datetime`, `threading`, `tkinter`.
  - External tool: `tcpdump` for packet capture.
- **Platforms:**
  - Kali Linux (bare metal or virtual machine).
  - WSL2 with Kali Linux on Windows (captures IP traffic via `eth0`).

## Prerequisites

### 1. Operating System

- Kali Linux (recommended), or  
- WSL2 with Kali Linux distribution on Windows 10/11.

### 2. Packages

Install the following in Kali / WSL:

```bash
sudo apt update
sudo apt install python3 python3-tk tcpdump
```

Check tcpdump:

```bash
tcpdump --version
```

### 3. Permissions

Raw packet capture requires elevated privileges:

```bash
sudo python3 network_sniffer_gui.py
```

## Installation

1. **Clone the Repository**

```bash
git clone https://github.com/<your-username>/network-sniffer-gui.git
cd network-sniffer-gui
```

1. **Verify Dependencies**

Ensure `tcpdump` and `python3-tk` are installed as shown in the prerequisites.

1. **Place the Script**

Make sure your main script file is named something like:

```text
network_sniffer_gui.py
```

(Use the full script from this project.)

## Usage

### 1. Run the Application

```bash
sudo python3 network_sniffer_gui.py
```

> **Note:** `sudo` is mandatory for access to raw packet capture on Linux-based systems.

### 2. Select Interface

- On Kali VM / bare metal:
  - You might see `eth0`, `wlan0`, etc.
- On WSL2:
  - Typically you see `eth0` (virtual NIC) and `lo`.

Choose the desired interface from the dropdown and click **Start Sniffing**.

### 3. Capture Traffic

- Generate traffic by:
  - Browsing websites.
  - Running `ping` or `curl`.
  - Using other apps that access the network.

Packets will appear in the **Captured Packets** table with:

- Time  
- Source IP:Port  
- Destination IP:Port  
- Protocol  
- Type (HTTP, DNS, etc., where inferrable)  
- Length (bytes)

### 4. View Packet Details

- Click on any row in the packet table.
- The **Packet Details** pane will show:
  - Timestamp, MAC addresses, IPs, ports.
  - Protocol and inferred application type.
  - Payload preview (first bytes, decoded when possible).
- The **Hex View** pane shows a hex dump with offsets for deeper analysis.

### 5. Export Data

- **Export JSON:** Save all captured packets as a JSON array of objects.
- **Export CSV:** Save all captured packets as a CSV file for use in Excel / Pandas.

Use the **Export JSON** and **Export CSV** buttons in the Control Panel.

## Example Commands & Flows

### Example: Basic Run on Kali

```bash
sudo apt update
sudo apt install tcpdump python3-tk
git clone https://github.com/<your-username>/network-sniffer-gui.git
cd network_sniffer-gui
sudo python3 network_sniffer_gui.py
```

Select `eth0` and click **Start Sniffing**, then in another terminal:

```bash
ping -c 4 8.8.8.8
```

The ICMP packets should appear in the GUI.

### Example: Viewing DNS & HTTP

- Open browser to some websites or run:
    bash
  dig google.com
  curl <http://example.com>

- The sniffer will classify relevant packets as:
  - Protocol: UDP, Type: DNS (port 53).
  - Protocol: TCP, Type: HTTP (port 80) or HTTPS (443).

## Limitations

- **WSL2 Wi‑Fi Access:**  
  WSL2 does **not expose the physical Wi‑Fi adapter** directly; you can only see IP traffic that flows over the virtual `eth0` interface, not raw 802.11 Wi‑Fi management frames.

- **Monitor Mode:**  
  True monitor-mode Wi‑Fi capture (`wlan0` in monitor mode) requires a full Linux environment with a compatible Wi‑Fi adapter; this is not supported natively inside WSL2:

- **Protocol Coverage:**  
  The tool focuses on Ethernet + IPv4 with basic TCP/UDP/ICMP/ARP parsing. Advanced protocol decoders (e.g., full HTTP header parsing, TLS/SSL, IPv6) are not included yet.

- **Filtering:**  
  Currently, there is no GUI-based filter for BPF expressions; all packets from the selected interface are analyzed.

## Roadmap / Future Enhancements

- Add **capture filters** (e.g., by protocol, IP, port) using tcpdump expressions.
- Extend support to **IPv6** and additional protocols.  
- Implement **alerting/anomaly detection** (e.g., suspicious ports, SYN floods, scans).  
- Add **graphical charts** for traffic volume and protocol distribution over time.  
- Optional integration with **Scapy** for crafting packets and more detailed analysis.

## Project Structure

A typical repository layout:

text
.
├── network_sniffer_gui.py   # Main application (GUI + sniffer logic)
├── README.md                # Project documentation
├── requirements.txt         # (Optional) Python dependencies
└── captures/                # (Optional) Exported JSON/CSV files

## Credits

- **Developer:**  
  **Narendra Borhade**  
  Student ID: **CA/DF1/6646**  

- **Organization / Internship Provider:**  
  **CODE ALPHA**
