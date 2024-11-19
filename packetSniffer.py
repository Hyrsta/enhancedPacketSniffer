import tkinter as tk
from tkinter import ttk, filedialog, messagebox, StringVar, Menu
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, Ether, get_if_list
from scapy.sessions import IPSession  # Import IPSession
import threading
import json
import os  # Added import

# Optional: Import HTTP layers if scapy-http is installed
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_HTTP_AVAILABLE = True
except ImportError:
    SCAPY_HTTP_AVAILABLE = False

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Packet Sniffer with Comprehensive Protocol Parsing")
        self.root.geometry("1300x700")  # Adjusted window size for better layout

        self.style = ttk.Style()
        self.style.theme_use("default")  # Ensure default theme is used

        self.create_widgets()
        self.sniffing = False
        self.packets = []  # List to store captured packets as dictionaries
        self.filtered_packets = []  # List to store packets matching display filters
        self.packet_count = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "Other": 0,
            "ARP": 0,
            "HTTP Request": 0,
            "HTTP Response": 0
        }

        self.dark_mode = False  # Flag to track current theme
        self.setup_styles()  # Setup initial styles

    def setup_styles(self):
        # Light Mode Styles
        self.style.configure("Treeview",
                             background="white",
                             foreground="black",
                             fieldbackground="white",
                             rowheight=25)
        self.style.map("Treeview",
                       background=[('selected', '#347083')])

        # Dark Mode Styles
        self.style.configure("Treeview.Dark",
                             background="#2E2E2E",
                             foreground="white",
                             fieldbackground="#2E2E2E",
                             rowheight=25)
        self.style.map("Treeview.Dark",
                       background=[('selected', '#347083')])

        # Entry and Combobox Styles
        self.style.configure("TEntry",
                             fieldbackground="white",
                             foreground="black")
        self.style.configure("TCombobox",
                             fieldbackground="white",
                             foreground="black")

        self.style.configure("TLabel",
                             background="white",
                             foreground="black")
        self.style.configure("TButton",
                             background="white",
                             foreground="black")

    def create_widgets(self):
        # Create a menu bar
        self.menubar = Menu(self.root)
        self.root.config(menu=self.menubar)

        # Create file menu and keep a reference to it
        self.file_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Start Sniffing", command=self.start_sniffing)
        self.file_menu.add_command(label="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Export Logs", command=self.export_logs)
        self.file_menu.add_command(label="Import Logs", command=self.import_logs)  # Added Import Logs
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Save Configuration", command=self.save_configuration)
        self.file_menu.add_command(label="Load Configuration", command=self.load_configuration)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)

        # Create view menu
        self.view_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)

        # Create a toolbar frame for capture options (only Interface selection)
        capture_toolbar = tk.LabelFrame(self.root, text="Capture Options")
        capture_toolbar.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W+tk.E)

        # Network interface selection
        tk.Label(capture_toolbar, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_var = StringVar()
        self.interface_menu = ttk.Combobox(capture_toolbar, textvariable=self.interface_var, width=50)

        # Modify interface list for user-friendly names
        if os.name == 'nt':
            # Windows systems
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                interface_descriptions = [iface['description'] for iface in interfaces]
                interface_names = [iface['name'] for iface in interfaces]
                self.interface_mapping = dict(zip(interface_descriptions, interface_names))
                self.interface_menu['values'] = interface_descriptions
            except ImportError:
                messagebox.showerror("Error", "Scapy Windows interface list retrieval failed.")
                self.interface_menu['values'] = []
        else:
            # Unix/Linux/MacOS systems
            interfaces = get_if_list()
            self.interface_mapping = dict(zip(interfaces, interfaces))
            self.interface_menu['values'] = interfaces

        if interfaces:
            self.interface_menu.current(0)
        self.interface_menu.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Protocol filter options (Display Filters)
        display_toolbar = tk.LabelFrame(self.root, text="Display Filters")
        display_toolbar.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W+tk.E)

        # Protocol Filter
        tk.Label(display_toolbar, text="Protocol:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.display_protocol_var = StringVar(value="ALL")
        self.display_protocol_menu = ttk.Combobox(display_toolbar, textvariable=self.display_protocol_var, width=20)
        self.display_protocol_menu['values'] = ["ALL", "TCP", "UDP", "ICMP", "ARP", "HTTP Request", "HTTP Response"]
        self.display_protocol_menu.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.display_protocol_menu.bind("<<ComboboxSelected>>", lambda e: self.apply_display_filters())

        # Source Address Filter
        tk.Label(display_toolbar, text="Source IP:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.source_ip_var = StringVar()
        self.source_ip_entry = ttk.Entry(display_toolbar, textvariable=self.source_ip_var, width=20)
        self.source_ip_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.source_ip_entry.bind("<KeyRelease>", lambda e: self.apply_display_filters())

        # Destination Address Filter
        tk.Label(display_toolbar, text="Destination IP:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.dest_ip_var = StringVar()
        self.dest_ip_entry = ttk.Entry(display_toolbar, textvariable=self.dest_ip_var, width=20)
        self.dest_ip_entry.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)
        self.dest_ip_entry.bind("<KeyRelease>", lambda e: self.apply_display_filters())

        # **Create a Frame to hold Treeview and Scrollbar**
        tree_frame = tk.Frame(self.root)
        tree_frame.grid(row=2, column=0, columnspan=8, padx=10, pady=10, sticky='nsew')

        # **Packet Table (Treeview)**
        self.packet_table = ttk.Treeview(tree_frame, columns=("No", "Source", "Destination", "Protocol", "Info"), show="headings")
        self.packet_table.heading("No", text="No")
        self.packet_table.heading("Source", text="Source")
        self.packet_table.heading("Destination", text="Destination")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Info", text="Info")
        self.packet_table.bind("<Double-1>", self.on_packet_select)

        # **Add Vertical Scrollbar**
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)

        # **Layout the Treeview and Scrollbar within the Frame**
        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Make the table expandable
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Statistics Panel
        self.stats_frame = tk.Frame(self.root)
        self.stats_frame.grid(row=3, column=0, columnspan=8, padx=10, pady=5, sticky=tk.W)

        self.tcp_count_label = tk.Label(self.stats_frame, text="TCP: 0")
        self.tcp_count_label.grid(row=0, column=0, padx=5)

        self.udp_count_label = tk.Label(self.stats_frame, text="UDP: 0")
        self.udp_count_label.grid(row=0, column=1, padx=5)

        self.icmp_count_label = tk.Label(self.stats_frame, text="ICMP: 0")
        self.icmp_count_label.grid(row=0, column=2, padx=5)

        self.arp_count_label = tk.Label(self.stats_frame, text="ARP: 0")
        self.arp_count_label.grid(row=0, column=3, padx=5)

        self.http_req_count_label = tk.Label(self.stats_frame, text="HTTP Requests: 0")
        self.http_req_count_label.grid(row=0, column=4, padx=5)

        self.http_resp_count_label = tk.Label(self.stats_frame, text="HTTP Responses: 0")
        self.http_resp_count_label.grid(row=0, column=5, padx=5)

        self.other_count_label = tk.Label(self.stats_frame, text="Other: 0")
        self.other_count_label.grid(row=0, column=6, padx=5)

        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=4, column=0, columnspan=8, sticky=tk.W+tk.E)

    def packet_callback(self, packet):
        # Initialize packet dictionary
        packet_dict = {
            "No": len(self.packets) + 1,
            "Ethernet": {},
            "IPv4": {},
            "TCP": {},
            "UDP": {},
            "HTTP": {},
            "ARP": {},
            "ICMP": {},
            "Other": {},
            "Protocol": "",
            "Info": ""
        }

        # **Parse Ethernet Layer**
        if Ether in packet:
            eth_layer = packet[Ether]
            packet_dict["Ethernet"] = {
                "Source MAC": eth_layer.src,
                "Destination MAC": eth_layer.dst,
                "Type": eth_layer.type
            }

        # **Parse IPv4 Layer**
        if IP in packet:
            ip_layer = packet[IP]
            packet_dict["IPv4"] = {
                "Source IP": ip_layer.src,
                "Destination IP": ip_layer.dst,
                "TTL": ip_layer.ttl,
                "Flags": str(ip_layer.flags),  # Convert FlagValue to string
                "Fragment Offset": ip_layer.frag,
                "Header Length": ip_layer.ihl * 4  # in bytes
            }
            proto_num = ip_layer.proto
            protocol = self.get_protocol(proto_num)
            packet_dict["Protocol"] = protocol
        else:
            # If not IPv4, attempt to parse other layers like ARP
            if ARP in packet:
                protocol = "ARP"
                packet_dict["Protocol"] = protocol
            else:
                protocol = "Other"
                packet_dict["Protocol"] = protocol

        # **Parse TCP Layer**
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_dict["TCP"] = {
                "Source Port": tcp_layer.sport,
                "Destination Port": tcp_layer.dport,
                "Sequence Number": tcp_layer.seq,
                "Acknowledgment Number": tcp_layer.ack,
                "Flags": str(tcp_layer.flags),  # Convert FlagValue to string
                "Window Size": tcp_layer.window
            }

        # **Parse UDP Layer**
        if UDP in packet:
            udp_layer = packet[UDP]
            packet_dict["UDP"] = {
                "Source Port": udp_layer.sport,
                "Destination Port": udp_layer.dport,
                "Length": udp_layer.len
            }

        # **Parse HTTP Layer**
        if SCAPY_HTTP_AVAILABLE:
            if protocol == "HTTP Request" and packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                packet_dict["HTTP"] = {
                    "Method": http_layer.Method.decode(errors='replace') if isinstance(http_layer.Method, bytes) else http_layer.Method,
                    "Host": http_layer.Host.decode(errors='replace') if isinstance(http_layer.Host, bytes) else http_layer.Host,
                    "Path": http_layer.Path.decode(errors='replace') if isinstance(http_layer.Path, bytes) else http_layer.Path,
                    "User-Agent": http_layer.User_Agent.decode(errors='replace') if hasattr(http_layer, 'User_Agent') and isinstance(http_layer.User_Agent, bytes) else getattr(http_layer, 'User_Agent', 'N/A')
                }
                self.packet_count["HTTP Request"] += 1
            elif protocol == "HTTP Response" and packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]
                packet_dict["HTTP"] = {
                    "Status": http_layer.Status.decode(errors='replace') if isinstance(http_layer.Status, bytes) else http_layer.Status,
                    "Reason": http_layer.Reason.decode(errors='replace') if hasattr(http_layer, 'Reason') and isinstance(http_layer.Reason, bytes) else getattr(http_layer, 'Reason', 'N/A')
                }
                self.packet_count["HTTP Response"] += 1
        else:
            # Notify that HTTP parsing is unavailable
            if protocol in ["HTTP Request", "HTTP Response"]:
                packet_dict["HTTP"] = {"Info": "HTTP Parsing Not Available"}

        # **Parse ARP Layer**
        if ARP in packet:
            arp_layer = packet[ARP]
            packet_dict["ARP"] = {
                "Operation": "who-has" if arp_layer.op == 1 else "is-at",
                "Sender MAC": arp_layer.hwsrc,
                "Sender IP": arp_layer.psrc,
                "Target MAC": arp_layer.hwdst,
                "Target IP": arp_layer.pdst
            }
            self.packet_count["ARP"] += 1

        # **Parse ICMP Layer**
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_dict["ICMP"] = {
                "Type": icmp_layer.type,
                "Code": icmp_layer.code,
                "Checksum": icmp_layer.chksum
            }
            self.packet_count["ICMP"] += 1

        # **Handle Raw Data**
        if Raw in packet:
            raw_data = packet[Raw].load
            packet_dict["Raw Data"] = raw_data.hex()

        # **Determine Protocol Type and Info for Display**
        info_parts = []
        if Ether in packet:
            eth = packet_dict["Ethernet"]
            info_parts.append(f"Ethernet: {eth['Source MAC']} -> {eth['Destination MAC']} | Type: {eth['Type']}")

        if IP in packet:
            ipv4 = packet_dict["IPv4"]
            info_parts.append(f"IPv4: {ipv4['Source IP']} -> {ipv4['Destination IP']} | TTL: {ipv4['TTL']} | Flags: {ipv4['Flags']} | Frag Offset: {ipv4['Fragment Offset']} | Header Length: {ipv4['Header Length']} bytes")

        if TCP in packet:
            tcp = packet_dict["TCP"]
            info_parts.append(f"TCP: {tcp['Source Port']} -> {tcp['Destination Port']} | Seq: {tcp['Sequence Number']} | Ack: {tcp['Acknowledgment Number']} | Flags: {tcp['Flags']} | Window: {tcp['Window Size']}")

        if UDP in packet:
            udp = packet_dict["UDP"]
            info_parts.append(f"UDP: {udp['Source Port']} -> {udp['Destination Port']} | Length: {udp['Length']}")

        if HTTPRequest in packet:
            http = packet_dict["HTTP"]
            info_parts.append(f"HTTP Request: {http.get('Method', 'N/A')} {http.get('Host', 'N/A')}{http.get('Path', '')} | User-Agent: {http.get('User-Agent', 'N/A')}")
            
        if HTTPResponse in packet:
            http = packet_dict["HTTP"]
            info_parts.append(f"HTTP Response: {http.get('Status', 'N/A')} {http.get('Reason', 'N/A')}")

        if ARP in packet:
            arp = packet_dict["ARP"]
            info_parts.append(f"ARP: {arp['Operation']} {arp['Target IP']} | Sender: {arp['Sender MAC']} ({arp['Sender IP']}) -> Target: {arp['Target MAC']} ({arp['Target IP']})")

        if ICMP in packet:
            icmp = packet_dict["ICMP"]
            info_parts.append(f"ICMP: Type {icmp['Type']} | Code {icmp['Code']} | Checksum {icmp['Checksum']}")

        if Raw in packet:
            raw_hex = packet_dict.get("Raw Data", "")
            info_parts.append(f"Raw Data: {raw_hex[:100]}...")  # Limit displayed data to prevent lag

        # Combine all info parts
        packet_dict["Info"] = " | ".join(info_parts)

        # **Update Packet Counts**
        if protocol in self.packet_count:
            if protocol in ["HTTP Request", "HTTP Response"]:
                # Counts already updated above
                pass
            else:
                self.packet_count[protocol] += 1
        else:
            self.packet_count["Other"] += 1

        # **Add Packet to Packets List**
        self.packets.append(packet_dict)

        # **Apply Display Filters Before Inserting**
        if self.packet_matches_filters(packet_dict):
            self.insert_packet_into_table(packet_dict)

        # **Update Statistics**
        self.update_stats()

    def get_protocol(self, proto_num):
        if proto_num == 6:
            return "TCP"
        elif proto_num == 17:
            return "UDP"
        elif proto_num == 1:
            return "ICMP"
        elif proto_num == 0x0806:
            return "ARP"
        elif SCAPY_HTTP_AVAILABLE and (proto_num == 80 or proto_num == 443):
            return "HTTP Request" if proto_num == 80 else "HTTP Response"
        else:
            return "Other"

    def insert_packet_into_table(self, packet_dict):
        # Insert the packet into the Treeview
        self.packet_table.insert("", "end", values=(
            packet_dict["No"],
            packet_dict["IPv4"].get("Source IP", "N/A"),
            packet_dict["IPv4"].get("Destination IP", "N/A"),
            packet_dict["Protocol"],
            packet_dict["Info"]
        ))
        # **Automatically scroll to the latest packet**
        self.packet_table.see(self.packet_table.get_children()[-1])

    def start_sniffing(self):
        if not self.interface_mapping:
            messagebox.showerror("Error", "No network interfaces found.")
            return

        self.sniffing = True
        self.status_bar.config(text="Sniffing in progress...")
        self.packets.clear()
        self.filtered_packets.clear()
        self.packet_table.delete(*self.packet_table.get_children())  # Clear previous entries

        # Get selected interface
        selected_interface = self.interface_var.get()
        interface = self.interface_mapping.get(selected_interface, selected_interface)

        # Start sniffing in a separate thread with IPSession for IP fragment reassembly
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(interface,), daemon=True)
        self.sniffer_thread.start()

        # Enable stop menu item
        self.file_menu.entryconfig("Stop Sniffing", state="normal")

    def stop_sniffing(self):
        self.sniffing = False
        self.status_bar.config(text="Sniffing stopped.")

        # Disable stop menu item
        self.file_menu.entryconfig("Stop Sniffing", state="disabled")

    def sniff_packets(self, interface):
        try:
            sniff(prn=self.packet_callback,
                  iface=interface,
                  store=0,
                  session=IPSession,  # Use IPSession for IP fragment reassembly
                  stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during sniffing: {e}")
            self.stop_sniffing()

    def export_logs(self):
        if not self.packets:
            messagebox.showinfo("Info", "No logs to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json"),
                                                            ("Text files", "*.txt")])
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, "w") as file:
                        json.dump(self.packets, file, indent=4)
                else:
                    with open(file_path, "w") as file:
                        for pkt in self.packets:
                            file.write(json.dumps(pkt) + "\n")
                messagebox.showinfo("Success", "Logs exported successfully.")
            except TypeError as te:
                messagebox.showerror("Error", f"Failed to export logs: {te}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")

    def import_logs(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"),
                                                          ("Text files", "*.txt")])
        if file_path:
            try:
                imported_packets = []
                if file_path.endswith('.json'):
                    with open(file_path, "r") as file:
                        imported_packets = json.load(file)
                else:
                    with open(file_path, "r") as file:
                        for line in file:
                            imported_packets.append(json.loads(line.strip()))
                
                self.packets.extend(imported_packets)
                self.apply_display_filters()
                messagebox.showinfo("Success", "Logs imported successfully.")
            except json.JSONDecodeError as jde:
                messagebox.showerror("Error", f"Failed to parse JSON: {jde}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import logs: {e}")

    def save_configuration(self):
        config = {
            "interface": self.interface_var.get(),
            "display_protocol": self.display_protocol_var.get(),
            "source_ip": self.source_ip_var.get(),
            "destination_ip": self.dest_ip_var.get()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, "w") as file:
                    json.dump(config, file, indent=4)
                messagebox.showinfo("Success", "Configuration saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {e}")

    def load_configuration(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, "r") as file:
                    config = json.load(file)
                    self.interface_var.set(config.get("interface", ""))
                    self.display_protocol_var.set(config.get("display_protocol", "ALL"))
                    self.source_ip_var.set(config.get("source_ip", ""))
                    self.dest_ip_var.set(config.get("destination_ip", ""))
                self.apply_display_filters()
                messagebox.showinfo("Success", "Configuration loaded successfully.")
            except json.JSONDecodeError as jde:
                messagebox.showerror("Error", f"Failed to parse JSON: {jde}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load configuration: {e}")

    def toggle_dark_mode(self):
        if not self.dark_mode:
            # Switch to Dark Mode
            self.style.configure("Treeview",
                                 background="#2E2E2E",
                                 foreground="white",
                                 fieldbackground="#2E2E2E")
            self.style.configure("TEntry",
                                 fieldbackground="#4D4D4D",
                                 foreground="white")
            self.style.configure("TCombobox",
                                 fieldbackground="#4D4D4D",
                                 foreground="white")
            self.style.configure("TLabel",
                                 background="#2E2E2E",
                                 foreground="white")
            self.style.configure("TButton",
                                 background="#2E2E2E",
                                 foreground="white")
            self.dark_mode = True
        else:
            # Switch to Light Mode
            self.style.configure("Treeview",
                                 background="white",
                                 foreground="black",
                                 fieldbackground="white")
            self.style.configure("TEntry",
                                 fieldbackground="white",
                                 foreground="black")
            self.style.configure("TCombobox",
                                 fieldbackground="white",
                                 foreground="black")
            self.style.configure("TLabel",
                                 background="white",
                                 foreground="black")
            self.style.configure("TButton",
                                 background="white",
                                 foreground="black")
            self.dark_mode = False

    def update_stats(self):
        self.tcp_count_label.config(text=f"TCP: {self.packet_count.get('TCP',0)}")
        self.udp_count_label.config(text=f"UDP: {self.packet_count.get('UDP',0)}")
        self.icmp_count_label.config(text=f"ICMP: {self.packet_count.get('ICMP',0)}")
        self.arp_count_label.config(text=f"ARP: {self.packet_count.get('ARP',0)}")
        self.http_req_count_label.config(text=f"HTTP Requests: {self.packet_count.get('HTTP Request',0)}")
        self.http_resp_count_label.config(text=f"HTTP Responses: {self.packet_count.get('HTTP Response',0)}")
        self.other_count_label.config(text=f"Other: {self.packet_count.get('Other',0)}")

    def apply_display_filters(self):
        # Clear current Treeview
        self.packet_table.delete(*self.packet_table.get_children())
        self.filtered_packets.clear()

        # Get filter criteria
        protocol_filter = self.display_protocol_var.get().lower()
        source_ip_filter = self.source_ip_var.get().strip().lower()
        dest_ip_filter = self.dest_ip_var.get().strip().lower()

        for pkt in self.packets:
            if self.packet_matches_filters(pkt):
                self.filtered_packets.append(pkt)
                self.insert_packet_into_table(pkt)

    def packet_matches_filters(self, pkt):
        # Protocol filter
        protocol_filter = self.display_protocol_var.get().lower()
        if protocol_filter != "all" and pkt["Protocol"].lower() != protocol_filter:
            return False

        # Source IP filter
        source_ip_filter = self.source_ip_var.get().strip().lower()
        if source_ip_filter:
            # Check if Source IP matches or contains the filter string
            src_ip = pkt["IPv4"].get("Source IP", "").lower()
            if source_ip_filter not in src_ip:
                return False

        # Destination IP filter
        dest_ip_filter = self.dest_ip_var.get().strip().lower()
        if dest_ip_filter:
            # Check if Destination IP matches or contains the filter string
            dst_ip = pkt["IPv4"].get("Destination IP", "").lower()
            if dest_ip_filter not in dst_ip:
                return False

        return True

    def on_packet_select(self, event):
        selected_item = self.packet_table.selection()
        if selected_item:
            packet_info = self.packet_table.item(selected_item[0], "values")
            packet_no = packet_info[0]
            # Retrieve the full packet dictionary
            packet_dict = next((pkt for pkt in self.packets if pkt["No"] == int(packet_no)), None)
            if packet_dict:
                detailed_info = self.format_packet_details(packet_dict)
                messagebox.showinfo("Packet Details", detailed_info)

    def format_packet_details(self, pkt):
        details = f"Packet No: {pkt['No']}\n\n"

        # **Ethernet Details**
        if pkt["Ethernet"]:
            eth = pkt["Ethernet"]
            details += "=== Ethernet Layer ===\n"
            details += f"Source MAC Address: {eth.get('Source MAC', 'N/A')}\n"
            details += f"Destination MAC Address: {eth.get('Destination MAC', 'N/A')}\n"
            details += f"EtherType: {eth.get('Type', 'N/A')}\n\n"

        # **IPv4 Details**
        if pkt["IPv4"]:
            ipv4 = pkt["IPv4"]
            details += "=== IPv4 Layer ===\n"
            details += f"Source IP Address: {ipv4.get('Source IP', 'N/A')}\n"
            details += f"Destination IP Address: {ipv4.get('Destination IP', 'N/A')}\n"
            details += f"TTL: {ipv4.get('TTL', 'N/A')}\n"
            details += f"Flags: {ipv4.get('Flags', 'N/A')}\n"
            details += f"Fragment Offset: {ipv4.get('Fragment Offset', 'N/A')}\n"
            details += f"Header Length: {ipv4.get('Header Length', 'N/A')} bytes\n\n"

        # **TCP Details**
        if pkt["TCP"]:
            tcp = pkt["TCP"]
            details += "=== TCP Layer ===\n"
            details += f"Source Port: {tcp.get('Source Port', 'N/A')}\n"
            details += f"Destination Port: {tcp.get('Destination Port', 'N/A')}\n"
            details += f"Sequence Number: {tcp.get('Sequence Number', 'N/A')}\n"
            details += f"Acknowledgment Number: {tcp.get('Acknowledgment Number', 'N/A')}\n"
            details += f"Flags: {tcp.get('Flags', 'N/A')}\n"
            details += f"Window Size: {tcp.get('Window Size', 'N/A')}\n\n"

        # **UDP Details**
        if pkt["UDP"]:
            udp = pkt["UDP"]
            details += "=== UDP Layer ===\n"
            details += f"Source Port: {udp.get('Source Port', 'N/A')}\n"
            details += f"Destination Port: {udp.get('Destination Port', 'N/A')}\n"
            details += f"Length: {udp.get('Length', 'N/A')}\n\n"

        # **HTTP Details**
        if pkt["HTTP"]:
            http = pkt["HTTP"]
            details += "=== HTTP Layer ===\n"
            for key, value in http.items():
                details += f"{key}: {value}\n"
            details += "\n"

        # **ARP Details**
        if pkt["ARP"]:
            arp = pkt["ARP"]
            details += "=== ARP Layer ===\n"
            details += f"Operation: {arp.get('Operation', 'N/A')}\n"
            details += f"Sender MAC Address: {arp.get('Sender MAC', 'N/A')}\n"
            details += f"Sender IP Address: {arp.get('Sender IP', 'N/A')}\n"
            details += f"Target MAC Address: {arp.get('Target MAC', 'N/A')}\n"
            details += f"Target IP Address: {arp.get('Target IP', 'N/A')}\n\n"

        # **ICMP Details**
        if pkt["ICMP"]:
            icmp = pkt["ICMP"]
            details += "=== ICMP Layer ===\n"
            details += f"Type: {icmp.get('Type', 'N/A')}\n"
            details += f"Code: {icmp.get('Code', 'N/A')}\n"
            details += f"Checksum: {icmp.get('Checksum', 'N/A')}\n\n"

        # **Other Details**
        if pkt["Other"]:
            other = pkt["Other"]
            details += "=== Other Layer ===\n"
            for key, value in other.items():
                details += f"{key}: {value}\n"
            details += "\n"

        # **Raw Data**
        if pkt.get("Raw Data"):
            raw_data = pkt["Raw Data"]
            details += "=== Raw Data ===\n"
            details += f"{raw_data}\n\n"

        return details

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
