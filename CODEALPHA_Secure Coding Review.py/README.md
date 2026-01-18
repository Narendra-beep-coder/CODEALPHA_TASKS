# Advanced Network Sniffer (Scapy + Tkinter)

A Python-based **network packet sniffer with GUI** that captures, decodes, and visualizes live network traffic using Scapy and Tkinter.  
Developed as a security and networking project under **CODE ALPHA** by **Narendra Borhade (Student ID: CA/DF1/6646)** for the **Academic Year 2025–2026**.

---

## 1. Target and tools overview

- **Language:** Python 3.x  
- **Application:** `updated_Sniffer.py` – GUI packet sniffer using Scapy `sniff()` for live capture and protocol decoding (HTTP, DNS, RTP, Raw).  
- **Static analysis tools (run locally):**
  - `bandit -r .` for Python security issues such as hardcoded secrets, insecure functions, or unsafe subprocess usage.
  - `pylint` / `flake8` for code quality and bug-prone patterns (optional but recommended).

---

## 2. Project overview

This application provides an interactive interface to:

- Capture live packets from a selected network interface using Scapy’s `sniff()` function.  
- Display high-level metadata: timestamp, source/destination IP, protocol, and packet length in a sortable table.  
- Decode application protocols such as HTTP, DNS, and RTP where applicable.  
- Inspect packet details including IP/TCP/UDP headers, protocol-specific fields, and raw payload previews.

It targets educational usage in **network monitoring, traffic analysis, and secure coding practice** for Python-based security tools.

---

## 3. Features

- **Graphical User Interface (Tkinter)**  
  - Interface selection (dropdown) populated from system interfaces via `get_if_list()`.  
  - Optional BPF filter string for focused capture (for example `port 80`, `udp`, `host 8.8.8.8`).  
  - Start/Stop controls with clean threading and shutdown behavior.

- **Protocol decoding**  
  - IP, TCP, UDP header inspection (addresses, ports, flags, sequence numbers).  
  - HTTP request/response fields (method, path, host, status code).  
  - DNS queries and answers (qname, type, rcode).  
  - RTP header fields and payload length for VoIP-style traffic.

- **Safe payload inspection**  
  - **Safe Payload Mode (default)** shows only a limited preview of raw payload bytes (hex + decoded), minimizing exposure of sensitive data.  
  - Full payload view can be enabled manually for deep analysis when appropriate and authorized.

- **Resource protection**  
  - Configurable caps on the number of packets kept in memory and number of rows in the GUI to prevent memory or GUI denial-of-service on high-traffic interfaces.

---

## 4. Installation and usage

### 4.1 Prerequisites

- Python 3.x installed on:
  - Kali Linux (native or WSL2).  
  - Other Linux environments with Scapy support.  
- Administrator/root privileges (for example `sudo`) for live packet capture on most systems.

### 4.2 Setup

Clone the repository and navigate into the project folder:

```bash
git clone https://github.com/Narendra-beep-coder/CODEALPHA_TASKS.git
cd "CODEALPHA_TASKS/CODE ALPHA_Basic Network Sniffer"
```

Create and activate a virtual environment (recommended):

#### Linux / WSL

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows PowerShell

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install scapy
pip install tk  # if your environment requires a separate Tk package
```

> Note: On Kali/WSL, you may also need system packages for X/GUI support, for example:
>
> ```bash
> sudo apt install python3-tk
> ```

### 4.3 Running the sniffer

Run the GUI as root/admin to allow packet capture:

```bash
sudo python3 updated_Sniffer.py
```

Steps:

1. Select the network interface from the dropdown (for example `eth0`, `wlan0`, or the WSL virtual interface).  
2. Optionally enter a BPF filter (for example `port 80` or `udp`).  
3. Ensure **Safe Payload Mode** is checked if you want to avoid full payload exposure.  
4. Click **Start Sniffing** to begin capture.  
5. Click **Stop** or close the window to stop capture and exit cleanly.

---

## 5. Code review – key findings

From manual review of `updated_Sniffer.py` (and the secure variant), important issues and risks in the original version are:

### 5.1 Unvalidated interface and filter input

- Interface and BPF filter were taken from free-text entries and passed directly to `sniff()`, so malformed filters could cause repeated errors or crashes.

### 5.2 Denial-of-service / resource exhaustion

- Packets were stored unbounded in `self.packets` and all rows kept in the Treeview, which can exhaust memory or freeze the GUI on busy links.

### 5.3 Sensitive data exposure via payload display

- Raw payloads (including HTTP bodies, credentials, cookies) were fully decoded and shown by default, which is risky on real networks.

### 5.4 Threading and shutdown safety

- Sniffing ran in a background thread, but GUI close and stop logic could leave capture running longer than expected and did not always clean up fully.

### 5.5 Error handling and robustness

- `sniff()` was not wrapped in robust `try/except`, so permission errors (no sudo), invalid interface, or bad filter could kill the sniff thread without a clear user message.

These are typical risks highlighted in Python secure-coding and network tools guidance: input validation, privilege handling, error reporting, and limiting resource usage.

---

## 6. Remediation steps and secure coding practices

The hardened version you can commit implements these remediations.

### 6.1 Safer interface and filter handling

- Use `get_if_list()` to populate an interface dropdown so users pick from real interfaces instead of arbitrary strings.  
- Strip filter text and rely on Scapy/BPF compile error inside `sniff()` wrapped in `try/except` to show a clear dialog if the filter is invalid.

### 6.2 Bounded memory and GUI updates

- Add constants such as `MAX_PACKETS_IN_MEMORY` and `MAX_TREE_ROWS` and remove the oldest packet/row once the cap is reached to prevent memory and GUI DoS.  
- Keep capture responsive on high-traffic networks.

### 6.3 Safe payload mode

- Introduce a **Safe Payload Mode** (checked by default) that only shows a limited payload preview (for example 256 bytes) and hides the rest unless the user explicitly disables safe mode.  
- This aligns with secure coding guidance to minimize unnecessary exposure of sensitive data.

### 6.4 Improved error handling around `sniff()`

- Wrap `sniff()` in `try/except/finally`; on failure, show a user-friendly error dialog (permissions, interface, filter) instead of silent crashes and always reset Start/Stop buttons.  
- This matches Bandit and Pylint recommendations to avoid bare failures and to surface errors clearly.

### 6.5 Clean shutdown and threading

- Implement `on_close()` to set `self.sniffing = False`, wait briefly for the sniff thread, and then close the window, so no background capture continues after the GUI is closed.

These changes reflect secure coding practices for input validation, least privilege, safe error handling, and data minimization.

---

## 7. Static analysis

This project is designed to be compatible with Python security static analyzers.

### 7.1 Bandit (Python security linter)

Install in your virtualenv:

```bash
pip install bandit
```

Run from the project root (inside `CODE ALPHA_Basic Network Sniffer`):

```bash
bandit -r .
```

Focus on avoiding:

- `eval`, `exec` on untrusted input.  
- Insecure XML parsing.  
- Hardcoded passwords.  
- Unsafe subprocess usage.

### 7.2 Pylint / Flake8

Install:

```bash
pip install pylint flake8
```

Run:

```bash
pylint updated_Sniffer.py
flake8 updated_Sniffer.py
```

Focus on improving code quality, maintainability, and catching bug-prone patterns such as unused variables and overly broad exception handlers.

You can include Bandit and Pylint reports as part of your academic project documentation to demonstrate secure coding checks.

---

## 8. Ethical and legal notice

This tool is intended **only for educational and authorized security testing**:

- Use it only on networks and systems you own or have explicit permission to test.  
- Capturing and inspecting traffic without authorization may violate privacy laws and institutional policies.

The author and CODE ALPHA are not responsible for misuse or damage caused by improper use of this project.

---

## 9. Future enhancements

Potential future improvements:

- Export captures to PCAP/JSON for offline analysis in Wireshark or custom tools.  
- Add protocol-specific views (for example HTTP request/response reconstruction, DNS timeline).  
- Integrate anomaly detection or simple IDS-style rules to highlight suspicious traffic patterns.

Contributions and suggestions are welcome via issues or pull requests in this repository.
