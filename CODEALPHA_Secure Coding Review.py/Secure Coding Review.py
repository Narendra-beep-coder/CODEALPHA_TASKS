import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from scapy.all import (
    sniff,
    Packet,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    bind_layers,
    get_if_list,
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.rtp import RTP

# ---------- Constants / limits ----------
MAX_PACKETS_IN_MEMORY = 1000       # cap packet list to prevent DoS
MAX_TREE_ROWS = 1000               # cap rows in GUI
MAX_PAYLOAD_PREVIEW = 256          # bytes in safe mode

# ---------- Port-based protocol bindings ----------
# HTTP over common ports
bind_layers(TCP, HTTP, sport=80)
bind_layers(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=8080)
bind_layers(TCP, HTTP, dport=8080)

# DNS over UDP 53
bind_layers(UDP, DNS, sport=53)
bind_layers(UDP, DNS, dport=53)

# Example RTP ports (adjust to your VoIP setup)
bind_layers(UDP, RTP, sport=5004)
bind_layers(UDP, RTP, dport=5004)


# ---------- Helpers ----------
def hexdump_bytes(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x} {hex_part:<{width*3}} {ascii_part}")
    return "\n".join(lines)


def looks_like_rtp(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    b0 = payload[0]
    version = (b0 & 0xC0) >> 6
    if version != 2:
        return False
    b1 = payload[1]
    pt = b1 & 0x7F
    return 0 <= pt <= 127


def to_str(
    obj,
    encoding: str = "utf-8",
    errors: str = "ignore",
    default: str = "",
) -> str:
    """Decode bytes to string safely, fallback to str()."""
    if obj is None:
        return default
    if isinstance(obj, (bytes, bytearray)):
        try:
            return bytes(obj).decode(encoding, errors=errors)
        except Exception:
            return str(obj)
    return str(obj)


# ---------- GUI Sniffer ----------
class PacketSnifferGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Network Sniffer (Scapy + Tkinter)")
        self.sniffing = False
        self.sniff_thread = None
        self.packets = []

        # populate interface list safely
        self.interfaces = self._get_interfaces_safe()

        # ===== Control bar =====
        ctrl_frame = ttk.Frame(master)
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(ctrl_frame, text="Interface:").pack(side=tk.LEFT)

        self.iface_var = tk.StringVar(value=self.interfaces[0] if self.interfaces else "")
        self.iface_combo = ttk.Combobox(
            ctrl_frame,
            textvariable=self.iface_var,
            values=self.interfaces,
            width=18,
            state="readonly" if self.interfaces else "normal",
        )
        self.iface_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(ctrl_frame, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar(value="")
        filter_entry = ttk.Entry(
            ctrl_frame,
            textvariable=self.filter_var,
            width=25,
        )
        filter_entry.pack(side=tk.LEFT, padx=5)

        self.safe_mode_var = tk.BooleanVar(value=True)
        self.safe_mode_check = ttk.Checkbutton(
            ctrl_frame,
            text="Safe payload mode",
            variable=self.safe_mode_var,
        )
        self.safe_mode_check.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(
            ctrl_frame,
            text="Start Sniffing",
            command=self.start_sniffing,
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(
            ctrl_frame,
            text="Stop",
            command=self.stop_sniffing,
            state=tk.DISABLED,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # ===== Packet list =====
        list_frame = ttk.Frame(master)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("no", "time", "src", "dst", "proto", "length")
        self.tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            height=15,
        )
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(
                col,
                width=110 if col != "no" else 50,
                anchor=tk.W,
            )
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(
            list_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview,
        )
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<ButtonRelease-1>", self.on_packet_select)

        # ===== Detail pane =====
        detail_frame = ttk.LabelFrame(master, text="Packet Details")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            height=18,
            wrap=tk.NONE,
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # handle window close cleanly
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- Interface helper ----------
    def _get_interfaces_safe(self):
        try:
            ifaces = get_if_list()
            # small sanitization: keep non-empty strings
            return [i for i in ifaces if isinstance(i, str) and i.strip()]
        except Exception as e:
            messagebox.showwarning(
                "Interface error",
                f"Could not list interfaces automatically: {e}\n"
                "You may need to type interface name manually.",
            )
            return []

    # ---------- Sniff control ----------
    def start_sniffing(self):
        if self.sniffing:
            return

        iface = self.iface_var.get().strip() or None
        bpf_filter = self.filter_var.get().strip() or None

        if not iface:
            messagebox.showerror("Input error", "Please select or enter a network interface.")
            return

        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.packets.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.sniff_thread = threading.Thread(
            target=self.sniff_packets,
            args=(iface, bpf_filter),
            daemon=True,
        )
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self, iface, bpf_filter):
        def _process(pkt: Packet):
            if not self.sniffing:
                return

            # cap memory
            if len(self.packets) >= MAX_PACKETS_IN_MEMORY:
                self.packets.pop(0)
                # also remove first row in tree (oldest)
                self.master.after(0, self._remove_oldest_row)

            index = len(self.packets)
            self.packets.append(pkt)

            ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))
            first = pkt[0]
            src = getattr(first, "src", "")
            dst = getattr(first, "dst", "")

            last = pkt.lastlayer()
            proto = last.name if last else pkt.__class__.__name__
            length = len(pkt)

            self.master.after(
                0,
                self._insert_packet_row,
                index,
                ts,
                src,
                dst,
                proto,
                length,
            )

        try:
            # basic "validation" of filter by letting scapy compile it;
            # if invalid, an exception will be raised.
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=_process,
                store=False,
                stop_filter=lambda p: not self.sniffing,
            )
        except Exception as e:
            # show user-friendly message instead of silent failure
            self.master.after(
                0,
                lambda: messagebox.showerror(
                    "Sniff error",
                    "Packet capture failed.\n\n"
                    f"Details: {e}\n\n"
                    "Check permissions (sudo), interface name, and filter syntax.",
                ),
            )
        finally:
            # ensure UI is reset
            self.master.after(0, self.stop_sniffing)

    def _remove_oldest_row(self):
        children = self.tree.get_children()
        if not children:
            return
        self.tree.delete(children[0])

    def _insert_packet_row(self, index, ts, src, dst, proto, length):
        # cap rows in tree to avoid GUI DoS
        children = self.tree.get_children()
        if len(children) >= MAX_TREE_ROWS:
            self.tree.delete(children[0])

        self.tree.insert(
            "",
            tk.END,
            iid=str(index),
            values=(index, ts, src, dst, proto, length),
        )

    # ---------- Detail view with protocol decode ----------
    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        try:
            idx = int(selected[0])
        except ValueError:
            return

        if idx < 0 or idx >= len(self.packets):
            return

        pkt = self.packets[idx]
        lines = []

        lines.append(f"Packet #{idx}")
        lines.append("=" * 80)

        # Summary
        try:
            lines.append(f"Summary: {pkt.summary()}")
        except Exception:
            pass

        # IP info
        if IP in pkt:
            ip = pkt[IP]
            lines.append("\n[IP Info]")
            ip_info = (
                f"src={ip.src} dst={ip.dst} ttl={ip.ttl}"
                f" proto={ip.proto}"
            )
            lines.append(ip_info)

        # TCP / UDP info
        if TCP in pkt:
            tcp = pkt[TCP]
            lines.append("\n[TCP Info]")
            lines.append(
                f"sport={tcp.sport} dport={tcp.dport} "
                f"seq={tcp.seq} ack={tcp.ack} flags={tcp.flags}"
            )
        elif UDP in pkt:
            udp = pkt[UDP]
            lines.append("\n[UDP Info]")
            lines.append(
                f"sport={udp.sport} dport={udp.dport} "
                f"len={udp.len}"
            )

        # ----- HTTP decode -----
        if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
            lines.append("\n[HTTP Info]")
            http_layer = (
                pkt[HTTPRequest] if pkt.haslayer(HTTPRequest) else pkt[HTTPResponse]
            )
            method = getattr(http_layer, "Method", None)
            host = getattr(http_layer, "Host", None)
            path = getattr(http_layer, "Path", None)
            status_code = getattr(http_layer, "Status_Code", None)
            reason = getattr(http_layer, "Reason_Phrase", None)

            if method:
                m = to_str(method)
                p = to_str(path, default="")
                lines.append(f"Request: {m} {p}")
            if host:
                h = to_str(host)
                lines.append(f"Host: {h}")
            if status_code:
                sc = to_str(status_code)
                rs = to_str(reason)
                lines.append(f"Status: {sc} {rs}")

        # ----- DNS decode -----
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            lines.append("\n[DNS Info]")
            lines.append(
                f"id={dns.id} qr={'response' if dns.qr else 'query'} "
                f"opcode={dns.opcode} rcode={dns.rcode}"
            )
            if dns.qd is not None and isinstance(dns.qd, DNSQR):
                qname = dns.qd.qname
                if isinstance(qname, (bytes, bytearray)):
                    qname = to_str(qname)
                lines.append(
                    f"Query: {qname} type={dns.qd.qtype} "
                    f"class={dns.qd.qclass}"
                )
            if dns.an is not None and isinstance(dns.an, DNSRR):
                an = dns.an
                an_name = an.rrname
                if isinstance(an_name, (bytes, bytearray)):
                    an_name = to_str(an_name)
                rdata = getattr(an, "rdata", "")
                if isinstance(rdata, (bytes, bytearray)):
                    rdata = to_str(rdata)
                lines.append(
                    f"Answer: {an_name} type={an.type} rdata={rdata}"
                )

        # ----- RTP decode (bound or heuristic) -----
        rtp_obj = None
        if pkt.haslayer(RTP):
            rtp_obj = pkt[RTP]
        elif UDP in pkt and Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
            if looks_like_rtp(raw_data):
                try:
                    rtp_obj = RTP(raw_data)
                except Exception:
                    rtp_obj = None

        if rtp_obj is not None:
            lines.append("\n[RTP Info]")
            rtp_info = (
                f"version={rtp_obj.version} "
                f"payload_type={rtp_obj.payload_type} "
                f"seq={rtp_obj.sequence} ts={rtp_obj.timestamp} "
                f"ssrc={rtp_obj.sourcesync}"
            )
            lines.append(rtp_info)
            try:
                rtp_payload = bytes(rtp_obj.payload)
                lines.append(f"RTP payload length={len(rtp_payload)} bytes")
            except Exception:
                pass

        # ----- Generic layer list -----
        lines.append("\n[Layers]")
        try:
            for layer in pkt.layers():
                try:
                    layer_obj = pkt[layer]
                    fields = dict(layer_obj.fields)
                except Exception:
                    fields = {}
                lines.append(f"- {layer.name}: {fields}")
        except Exception:
            lines.append("- (error reading layers)")

        # ----- Raw payload: hex + decoded -----
        payload = getattr(pkt, "load", None)
        if payload is not None and isinstance(payload, (bytes, bytearray)):
            data = bytes(payload)
            if self.safe_mode_var.get():
                # safe mode: limit payload size
                preview = data[:MAX_PAYLOAD_PREVIEW]
                lines.append(
                    f"\n[Raw Payload - Safe preview ({len(preview)} of {len(data)} bytes)]"
                )
                lines.append(hexdump_bytes(preview))
                lines.append("\n[Decoded preview]")
                decoded = to_str(preview, encoding="utf-8", errors="replace")
                lines.append(decoded)
                lines.append(
                    "\n(Full payload hidden in safe mode. Disable 'Safe payload mode' to view all bytes.)"
                )
            else:
                lines.append("\n[Raw Payload - Hex]")
                lines.append(hexdump_bytes(data))
                lines.append("\n[Raw Payload - Decoded]")
                try:
                    decoded = to_str(data, encoding="utf-8", errors="replace")
                    lines.append(decoded)
                except Exception:
                    lines.append(repr(payload))
        else:
            lines.append("\n[Raw Payload]")
            lines.append("(no raw payload)")

        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(lines))

    # ---------- Clean close ----------
    def on_close(self):
        self.sniffing = False
        # wait briefly for thread to stop
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.master.after(200, self.master.destroy)
        else:
            self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
