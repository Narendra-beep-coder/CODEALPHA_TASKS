#!/usr/bin/env python3
import os
import sys
import threading
from datetime import datetime
from collections import defaultdict, Counter
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import struct
import binascii
import csv
import json
import subprocess

def check_admin():
    """Check if running with admin/root privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

class NetworkPacket:
    """Class to represent a network packet with its properties"""
    def __init__(self, timestamp, src_ip, dst_ip, protocol,
                 src_port=None, dst_port=None, length=0,
                 payload="", raw_data=""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = length
        self.payload = payload
        self.raw_data = raw_data
        self.packet_type = self._determine_packet_type()

    def _determine_packet_type(self):
        """Determine the type of packet based on protocol and ports"""
        protocol_types = {
            "TCP": {
                80: "HTTP", 443: "HTTPS", 22: "SSH",
                21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP"
            },
            "UDP": {
                53: "DNS", 123: "NTP", 161: "SNMP"
            }
        }

        if self.protocol in protocol_types:
            for port, ptype in protocol_types[self.protocol].items():
                if self.src_port == port or self.dst_port == port:
                    return ptype
            return self.protocol
        return self.protocol if self.protocol in ["ICMP", "ARP"] else "Unknown"

    def to_dict(self):
        """Convert packet to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'length': self.length,
            'payload': self.payload[:100] if self.payload else "",
            'packet_type': self.packet_type
        }

class PacketAnalyzer:
    """Class to analyze network packets"""
    def __init__(self):
        self.packet_count = 0
        self.protocol_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.packet_list = []

    def analyze_packet(self, packet_data):
        """Analyze a single packet"""
        try:
            if len(packet_data) < 20:
                return None

            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet_data[:20])
            ihl = ip_header[0] & 0xF
            iph_length = ihl * 4
            protocol = ip_header[6]
            s_addr = socket.inet_ntoa(ip_header[8])
            d_addr = socket.inet_ntoa(ip_header[9])

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            length = len(packet_data)
            protocol_name = self._get_protocol_name(protocol)

            src_port = dst_port = None
            payload = ""

            # Parse TCP/UDP
            if protocol in (6, 17):  # TCP or UDP
                header_size = 20 if protocol == 6 else 8
                if len(packet_data) > iph_length + header_size:
                    transport_header = struct.unpack(
                        '!HH' + ('LLBBHHH' if protocol == 6 else 'HH'),
                        packet_data[iph_length:iph_length+header_size]
                    )
                    src_port = transport_header[0]
                    dst_port = transport_header[1]

                    # Extract payload
                    data_start = iph_length + header_size
                    if data_start < len(packet_data):
                        payload_data = packet_data[data_start:data_start+200]
                        try:
                            payload = payload_data.decode('utf-8', errors='ignore')
                            payload = ''.join(c for c in payload if c.isprintable() or c in '\t\n\r')
                        except:
                            payload = f"Binary data: {binascii.hexlify(payload_data[:50]).decode()}"

            # Update statistics
            self.packet_count += 1
            self.protocol_counts[protocol_name] += 1
            self.ip_counts[s_addr] += 1
            self.ip_counts[d_addr] += 1
            if src_port: self.port_counts[src_port] += 1
            if dst_port: self.port_counts[dst_port] += 1

            return NetworkPacket(
                timestamp=timestamp,
                src_ip=s_addr,
                dst_ip=d_addr,
                protocol=protocol_name,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                payload=payload,
                raw_data=str(packet_data)
            )
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return None

    def _get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocol_map = {
            1: "ICMP", 6: "TCP", 17: "UDP",
            41: "IPv6", 50: "ESP", 51: "AH",
            58: "ICMPv6", 132: "SCTP"
        }
        return protocol_map.get(protocol_num, f"Protocol-{protocol_num}")

    def get_statistics(self):
        """Get current statistics"""
        return {
            'total_packets': self.packet_count,
            'protocol_counts': dict(self.protocol_counts),
            'top_ips': dict(Counter(self.ip_counts).most_common(10)),
            'top_ports': dict(Counter(self.port_counts).most_common(10))
        }

    def reset_statistics(self):
        """Reset all statistics"""
        self.packet_count = 0
        self.protocol_counts.clear()
        self.ip_counts.clear()
        self.port_counts.clear()
        self.packet_list.clear()

class NetworkSniffer:
    """Main network sniffer class"""
    def __init__(self, interface=None):
        self.interface = interface
        self.is_sniffing = False
        self.sniffer_thread = None
        self.analyzer = PacketAnalyzer()
        self.packet_callback = None
        self.tcpdump_process = None

    def set_packet_callback(self, callback):
        self.packet_callback = callback

    def start_sniffing(self):
        if self.is_sniffing:
            return False

        try:
            interface = self.interface or "eth0"

            # Check tcpdump availability
            try:
                subprocess.run(["which", "tcpdump"], check=True,
                             capture_output=True, text=True)
            except:
                messagebox.showerror("Error", "tcpdump not found. Please install it.")
                return False

            self.tcpdump_process = subprocess.Popen(
                ["tcpdump", "-i", interface, "-l", "-n", "-U", "-w", "-"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.is_sniffing = True
            self.sniffer_thread = threading.Thread(target=self._read_tcpdump_output)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start tcpdump: {e}")
            return False

    def _read_tcpdump_output(self):
        try:
            while self.is_sniffing:
                packet_data = self.tcpdump_process.stdout.read(65565)
                if not packet_data:
                    break

                if len(packet_data) > 24:
                    packet_data = packet_data[24:]
                    analyzed = self.analyzer.analyze_packet(packet_data)
                    if analyzed and self.packet_callback:
                        self.packet_callback(analyzed)
        except Exception as e:
            print(f"Error reading tcpdump: {e}")
        finally:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.is_sniffing = False
        if hasattr(self, 'tcpdump_process') and self.tcpdump_process:
            try:
                self.tcpdump_process.terminate()
                self.tcpdump_process.wait(timeout=5)
            except:
                pass
            finally:
                self.tcpdump_process = None

    def get_statistics(self):
        return self.analyzer.get_statistics()

    def reset_statistics(self):
        self.analyzer.reset_statistics()

    def get_available_interfaces(self):
        try:
            result = subprocess.run(['ip', 'link', 'show'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ':' in line and '@' not in line:
                        interface = line.split(':')[1].strip()
                        if interface not in ['lo', 'docker0']:
                            interfaces.append(interface)
                return interfaces if interfaces else ["eth0"]
            return ["eth0"]
        except:
            return ["eth0"]

class NetworkSnifferUI:
    """Main UI class"""
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2b2b2b")

        self.sniffer = NetworkSniffer()
        self.sniffer.set_packet_callback(self.on_packet_captured)
        self.packet_data = []

        self.create_widgets()
        self.update_statistics()

    def create_widgets(self):
        """Create all UI widgets"""
        # Main layout
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # Title frame
        title_frame = tk.Frame(self.root, bg="#3c3f41")
        title_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        title_frame.grid_columnconfigure(1, weight=1)

        tk.Label(
            title_frame, text="Network Sniffer",
            font=("Arial", 16, "bold"), fg="white", bg="#3c3f41"
        ).grid(row=0, column=0, padx=10, pady=5)

        tk.Label(
            title_frame, text="Note: Requires admin privileges",
            font=("Arial", 10), fg="#ff6b6b", bg="#3c3f41"
        ).grid(row=0, column=1, padx=10, pady=5, sticky="e")

        # Control frame
        control_frame = tk.LabelFrame(
            self.root, text="Control Panel",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        control_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        control_frame.grid_columnconfigure(4, weight=1)

        # Interface selection
        tk.Label(
            control_frame, text="Interface:",
            font=("Arial", 10), bg="#2b2b2b", fg="white"
        ).grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            control_frame, textvariable=self.interface_var,
            state="readonly", width=20
        )
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Button(
            control_frame, text="Refresh",
            command=self.refresh_interfaces
        ).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Start",
            command=self.start_sniffing
        ).grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Stop",
            command=self.stop_sniffing
        ).grid(row=0, column=4, padx=5, pady=5)

        ttk.Button(
            control_frame, text="Clear",
            command=self.clear_data
        ).grid(row=0, column=5, padx=5, pady=5)

        # Packet list
        packet_frame = tk.LabelFrame(
            self.root, text="Captured Packets",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )

        columns = ("Time", "Source", "Destination", "Protocol", "Type", "Length")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")

        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)

        self.packet_tree.column("Time", width=180)
        self.packet_tree.column("Source", width=150)
        self.packet_tree.column("Destination", width=150)
        self.packet_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Statistics frame
        stats_frame = tk.LabelFrame(
            self.root, text="Statistics",
            font=("Arial", 12), bg="#2b2b2b", fg="white"
        )
        stats_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        self.stats_labels = {}
        stats_config = [
            ("Total Packets:", "total_packets"),
            ("Protocols:", "protocols"),
            ("Top IPs:", "top_ips"),
            ("Top Ports:", "top_ports")
        ]

        for i, (label_text, key) in enumerate(stats_config):
            tk.Label(
                stats_frame, text=label_text,
                font=("Arial", 10, "bold"), bg="#2b2b2b", fg="#4db8ff"
            ).grid(row=0, column=i*2, padx=10, pady=5, sticky="w")

            self.stats_labels[key] = tk.Label(
                stats_frame, text="0", font=("Arial", 10),
                bg="#2b2b2b", fg="white", width=20
            )
            self.stats_labels[key].grid(
                row=0, column=i*2+1, padx=5, pady=5, sticky="w"
            )

        # Initialize interface list
        self.refresh_interfaces()

    def refresh_interfaces(self):
        interfaces = self.sniffer.get_available_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_var.set(interfaces[0])

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        self.sniffer.interface = interface
        self.sniffer.reset_statistics()

        if self.sniffer.start_sniffing():
            self.packet_data = []
            self.packet_tree.delete(*self.packet_tree.get_children())

    def stop_sniffing(self):
        self.sniffer.stop_sniffing()

    def clear_data(self):
        if messagebox.askyesno("Confirm", "Clear all data?"):
            self.packet_data = []
            self.packet_tree.delete(*self.packet_tree.get_children())
            self.sniffer.reset_statistics()

    def on_packet_captured(self, packet):
        self.packet_data.append(packet)
        values = (
            packet.timestamp,
            f"{packet.src_ip}:{packet.src_port}" if packet.src_port else packet.src_ip,
            f"{packet.dst_ip}:{packet.dst_port}" if packet.dst_port else packet.dst_ip,
            packet.protocol,
            packet.packet_type,
            packet.length
        )
        self.packet_tree.insert("", tk.END, values=values)

        if len(self.packet_data) > 1000:
            items = self.packet_tree.get_children()
            if items:
                self.packet_tree.delete(items[0])
                self.packet_data.pop(0)

    def update_statistics(self):
        stats = self.sniffer.get_statistics()
        self.stats_labels['total_packets'].config(text=str(stats['total_packets']))
        self.stats_labels['protocols'].config(text=", ".join(
            [f"{k}:{v}" for k, v in list(stats['protocol_counts'].items())[:5]]
        ))
        self.stats_labels['top_ips'].config(text=", ".join(
            [f"{k}:{v}" for k, v in list(stats['top_ips'].items())[:3]]
        ))
        self.stats_labels['top_ports'].config(text=", ".join(
            [f"{k}:{v}" for k, v in list(stats['top_ports'].items())[:3]]
        ))
        self.root.after(1000, self.update_statistics)

def main():
    if not check_admin():
        messagebox.showerror(
            "Error",
            "This application requires administrator/root privileges.\n"
            "Windows: Right-click and 'Run as administrator'\n"
            "Linux/Mac: Use 'sudo'"
        )
        return

    try:
        root = tk.Tk()
        root.lift()
        root.attributes('-topmost', True)
        root.after_idle(root.attributes, '-topmost', False)
        app = NetworkSnifferUI(root)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()