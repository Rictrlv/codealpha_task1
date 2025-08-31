from scapy.all import sniff, IP, TCP, UDP
 
def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
 
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        else:
            proto_name = str(proto)
 
        print(f"[+] {src} --> {dst} | Protocol: {proto_name}")
 
        if TCP in packet or UDP in packet:
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]} ...")  # show first 50 bytes
 
print("Starting packet sniffer... Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=False)