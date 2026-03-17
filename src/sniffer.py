from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(f"{src_ip} -> {dst_ip} | {protocol} | {src_port} -> {dst_port}")

print("Starting packet capture... Press CTRL+C to stop")
sniff(prn=process_packet, store=False)
