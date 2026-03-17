import os
import threading
import csv
import binascii
import sqlite3
from dotenv import load_dotenv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation


# ================= DATABASE =================

def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", (os.getenv("APP_USER"), os.getenv("APP_PASSWORD")))
    conn.commit()
    conn.close()

# ================= LOGIN =================

def check_login():
    user = username_entry.get()
    pwd = password_entry.get()
    
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
    result = cur.fetchone()
    conn.close()
    
    if result:
        login_window.destroy()
        launch_sniffer()
    else:
        messagebox.showerror("Login Failed", "Invalid Credentials")

# ================= GLOBALS =================

sniffing = False
packet_count = 0
captured_packets = []

tcp_count = 0
udp_count = 0
total_bytes = 0

traffic_counter = {}
blacklisted_ips = set()

# FTP (21)
# SSH (22)
# Telnet (23)
# RDP (3389)
# Backdoor ports (4444)
# Proxy/web (8080)

suspicious_ports = [21, 22, 23, 3389, 4444, 8080]

# ================= ATTACK LOG =================

def log_attack(ip, port, attack_type):
    time_now = datetime.now().strftime("%H:%M:%S")
    with open("attack_logs.txt", "a") as f:
        f.write(f"[{time_now}] {attack_type} from {ip} port {port}\n")

# ================= SNIFFER =================

def start_sniff():
    global sniffing
    sniffing = True
    threading.Thread(target=sniff_packets, daemon=True).start()
    status_label.config(text="Status: Running")

def stop_sniff():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped")

def sniff_packets():
    sniff(prn=process_packet, iface=interface_var.get(), store=False)

def process_packet(packet):
    global packet_count, tcp_count, udp_count, total_bytes
    
    if not sniffing or IP not in packet:
        return
    
    total_bytes += len(packet)
    
    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"
    
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_count += 1
    
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        udp_count += 1
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # traffic counter
    traffic_counter[src_ip] = traffic_counter.get(src_ip, 0) + 1
    
    if traffic_counter[src_ip] == 50:
        blacklisted_ips.add(src_ip)
        log_attack(src_ip, "-", "Possible DoS")
        root.after(0, update_blacklist)
        root.after(0, lambda: messagebox.showwarning("⚠ ALERT", f"Possible DoS from {src_ip}"))
    
    if src_port in suspicious_ports or dst_port in suspicious_ports:
        attack_port = src_port if src_port in suspicious_ports else dst_port
        log_attack(src_ip, attack_port, "Suspicious Port")
        root.after(0, lambda: messagebox.showinfo("⚠ Port Alert", f"Suspicious port {attack_port} from {src_ip}"))
    
    row = (src_ip, dst_ip, protocol, src_port, dst_port, packet)
    captured_packets.append(row)
    
    root.after(0, lambda: table.insert("", tk.END, values=row[:5]))
    packet_count += 1
    
    root.after(0, lambda: counter_label.config(text=f"Packets: {packet_count}"))
    root.after(0, lambda: stats_label.config(text=f"TCP: {tcp_count} | UDP: {udp_count}"))
    root.after(0, lambda: table.yview_moveto(1))

def update_blacklist():
    blacklist_box.delete(0, tk.END)
    for ip in blacklisted_ips:
        blacklist_box.insert(tk.END, ip)

# ================= PACKET DETAILS =================

def show_packet_details(event):
    selected = table.focus()
    if not selected:
        return
    
    index = table.index(selected)
    if index >= len(captured_packets):
        return
        
    packet_row = captured_packets[index]
    packet = packet_row[5]
    
    detail = tk.Toplevel(root)
    detail.title("Packet Inspection")
    detail.geometry("700x520")
    detail.configure(bg="#0d1117")
    
    labels = ["Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port"]
    
    for i in range(5):
        tk.Label(detail, text=f"{labels[i]}:",
                 fg="#00ff9c", bg="#0d1117",
                 font=("Consolas", 10, "bold")).pack()
        tk.Label(detail, text=packet_row[i],
                 fg="white", bg="#0d1117").pack()
    
    text = tk.Text(detail, bg="#161b22", fg="#79c0ff", height=15, width=85)
    text.pack(pady=10)
    
    if Raw in packet:
        text.insert("end", binascii.hexlify(bytes(packet[Raw].load)).decode())
    else:
        text.insert("end", "No Raw Payload")

# ================= SAVE TO CSV =================

def save_to_csv():
    if not captured_packets:
        messagebox.showinfo("Info", "No packets to save")
        return
    
    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])
        writer.writerows([p[:5] for p in captured_packets])
    
    messagebox.showinfo("Saved", f"Packets saved to {filename}")

# ================= CLEAR TABLE =================

def clear_table():
    global packet_count, captured_packets, tcp_count, udp_count, total_bytes
    for row in table.get_children():
        table.delete(row)
    
    captured_packets = []
    packet_count = 0
    tcp_count = 0
    udp_count = 0
    total_bytes = 0
    traffic_counter.clear()
    
    counter_label.config(text="Packets: 0")
    stats_label.config(text="TCP: 0 | UDP: 0")

# ================= GRAPH =================

def show_graph():
    global anim
    fig, ax = plt.subplots(figsize=(8, 4))
    x = []
    y = []
    
    def update(frame):
        x.append(len(x))
        y.append(packet_count)
        ax.clear()
        ax.plot(x, y, color="#00ff9c", linewidth=2)
        ax.set_title("Live Traffic Graph", color="white", fontsize=12)
        ax.set_xlabel("Time", color="white")
        ax.set_ylabel("Packets", color="white")
        ax.tick_params(colors="white")
        ax.set_facecolor("#0d1117")
        fig.patch.set_facecolor("#0d1117")
        
    anim = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
    plt.show()

# ================= UPDATE SPEED =================

def update_speed():
    global total_bytes
    speed = total_bytes / 1024
    speed_label.config(text=f"Speed: {speed:.2f} KB/s")
    total_bytes = 0
    root.after(1000, update_speed)

# ================= GUI =================

def launch_sniffer():
    global root, table, counter_label, stats_label, status_label, interface_var, blacklist_box, speed_label
    
    root = tk.Tk()
    root.title("Cyber Packet Analyzer")
    root.geometry("1200x700")
    root.configure(bg="#0d1117")
    
    # Get interfaces
    interfaces = get_if_list()
    if not interfaces:
        messagebox.showerror("Error", "No network interfaces found!")
        return
        
    interface_var = tk.StringVar(value=interfaces[0])
    
    # Title
    title_label = tk.Label(root, text="🔍 PACKET SNIFFER & ANALYZER", 
                           fg="#00ff9c", bg="#0d1117", 
                           font=("Arial", 16, "bold"))
    title_label.pack(pady=10)
    
    # Top control frame
    top_frame = tk.Frame(root, bg="#0d1117")
    top_frame.pack(pady=10)
    
    # Interface selection
    tk.Label(top_frame, text="Interface:", fg="#00ff9c", bg="#0d1117", 
             font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5)
    interface_menu = tk.OptionMenu(top_frame, interface_var, *interfaces)
    interface_menu.config(bg="#161b22", fg="white", highlightbackground="#00ff9c", width=15)
    interface_menu["menu"].config(bg="#161b22", fg="white")
    interface_menu.grid(row=0, column=1, padx=5)
    
    # Buttons
    tk.Button(top_frame, text="▶ Start", command=start_sniff,
              bg="#2ea043", fg="white", width=8, font=("Arial", 9, "bold")).grid(row=0, column=2, padx=5)
    tk.Button(top_frame, text="■ Stop", command=stop_sniff,
              bg="#f85149", fg="white", width=8, font=("Arial", 9, "bold")).grid(row=0, column=3, padx=5)
    tk.Button(top_frame, text="📊 Graph", command=show_graph,
              bg="#8957e5", fg="white", width=8, font=("Arial", 9, "bold")).grid(row=0, column=4, padx=5)
    tk.Button(top_frame, text="💾 Save", command=save_to_csv,
              bg="#1f6feb", fg="white", width=8, font=("Arial", 9, "bold")).grid(row=0, column=5, padx=5)
    tk.Button(top_frame, text="🗑 Clear", command=clear_table,
              bg="#6e7681", fg="white", width=8, font=("Arial", 9, "bold")).grid(row=0, column=6, padx=5)
    
    # Status frame
    status_frame = tk.Frame(root, bg="#0d1117")
    status_frame.pack(pady=5)
    
    status_label = tk.Label(status_frame, text="Status: Stopped", 
                           fg="#f85149", bg="#0d1117", font=("Arial", 11, "bold"))
    status_label.grid(row=0, column=0, padx=10)
    
    counter_label = tk.Label(status_frame, text="Packets: 0", 
                            fg="#79c0ff", bg="#0d1117", font=("Arial", 11))
    counter_label.grid(row=0, column=1, padx=10)
    
    stats_label = tk.Label(status_frame, text="TCP: 0 | UDP: 0", 
                          fg="#d2a8ff", bg="#0d1117", font=("Arial", 11))
    stats_label.grid(row=0, column=2, padx=10)
    
    speed_label = tk.Label(status_frame, text="Speed: 0.00 KB/s", 
                          fg="#7ee3b8", bg="#0d1117", font=("Arial", 11))
    speed_label.grid(row=0, column=3, padx=10)
    
    # Main content frame
    content_frame = tk.Frame(root, bg="#0d1117")
    content_frame.pack(expand=True, fill="both", padx=10, pady=10)
    
    # Table frame (left side)
    table_frame = tk.Frame(content_frame, bg="#0d1117")
    table_frame.pack(side="left", expand=True, fill="both")
    
    cols = ("Src IP", "Dst IP", "Proto", "Src Port", "Dst Port")
    table = ttk.Treeview(table_frame, columns=cols, show="headings", height=20)
    
    # Style the treeview
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#161b22", foreground="white", 
                   fieldbackground="#161b22", rowheight=25)
    style.configure("Treeview.Heading", background="#0d1117", 
                   foreground="#00ff9c", font=("Arial", 10, "bold"))
    style.map("Treeview", background=[("selected", "#2ea043")])
    
    for c in cols:
        table.heading(c, text=c)
        table.column(c, width=170, anchor="center")
    
    # Add scrollbar
    table_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
    table.configure(yscrollcommand=table_scrollbar.set)
    
    table.pack(side="left", expand=True, fill="both")
    table_scrollbar.pack(side="right", fill="y")
    
    table.bind("<Double-1>", show_packet_details)
    
    # Blacklist panel (right side)
    side_frame = tk.Frame(content_frame, bg="#0d1117", width=250)
    side_frame.pack(side="right", fill="y", padx=(10, 0))
    side_frame.pack_propagate(False)
    
    tk.Label(side_frame, text="⚠ Blacklisted IPs",
             fg="#ff7b72", bg="#0d1117",
             font=("Arial", 12, "bold")).pack(pady=10)
    
    # Listbox with scrollbar
    listbox_frame = tk.Frame(side_frame, bg="#0d1117")
    listbox_frame.pack(expand=True, fill="both")
    
    blacklist_box = tk.Listbox(listbox_frame,
                               bg="#161b22",
                               fg="#ff7b72",
                               selectbackground="#f85149",
                               font=("Consolas", 10),
                               height=25)
    blacklist_box.pack(side="left", expand=True, fill="both", padx=(5, 0))
    
    list_scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=blacklist_box.yview)
    blacklist_box.configure(yscrollcommand=list_scrollbar.set)
    list_scrollbar.pack(side="right", fill="y")
    
    tk.Button(side_frame,
              text="Clear Blacklist",
              bg="#f85149",
              fg="white",
              font=("Arial", 10, "bold"),
              command=lambda: (blacklisted_ips.clear(), update_blacklist())
              ).pack(pady=10)
    
    # Start speed update
    update_speed()
    
    root.mainloop()

# ================= MAIN =================

if __name__ == "__main__":
    load_dotenv()
    init_db()
    
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("350x250")
    login_window.configure(bg="#0d1117")
    
    # Center the window
    login_window.eval('tk::PlaceWindow . center')
    
    tk.Label(login_window, text="🔐 PACKET ANALYZER LOGIN", 
             fg="#00ff9c", bg="#0d1117", 
             font=("Arial", 14, "bold")).pack(pady=15)
    
    tk.Label(login_window, text="Username", fg="#00ff9c", bg="#0d1117", 
             font=("Arial", 11, "bold")).pack()
    username_entry = tk.Entry(login_window, bg="#161b22", fg="white", 
                              insertbackground="white", font=("Arial", 11),
                              width=20)
    username_entry.pack(pady=5)
    
    tk.Label(login_window, text="Password", fg="#00ff9c", bg="#0d1117", 
             font=("Arial", 11, "bold")).pack()
    password_entry = tk.Entry(login_window, show="*", bg="#161b22", fg="white", 
                              insertbackground="white", font=("Arial", 11),
                              width=20)
    password_entry.pack(pady=5)
    
    tk.Button(login_window, text="Login", command=check_login,
              bg="#2ea043", fg="white", width=15, 
              font=("Arial", 11, "bold")).pack(pady=15)
    
    # Bind Enter key to login
    password_entry.bind("<Return>", lambda event: check_login())
    username_entry.bind("<Return>", lambda event: password_entry.focus())
    
    login_window.mainloop()
