from scapy.all import sniff, Raw, wrpcap
from datetime import datetime

mode = "summary"  # "summary" or "data"
print("Sniffing network in progress...")

port = 3000
n = 100
app = f"tcp port {port}"
interface = 'lo'

current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
traffic_file = f"traffic_{current_time}.pcap"
packets = []

def handle_packet(pkt):
    if mode == "summary":
        print(pkt.summary())
    elif mode == "data" and Raw in pkt:
        try:
            print(pkt[Raw].load.decode(errors='ignore'))
        except:
            pass
    packets.append(pkt)

sniff(filter=app, count=n, iface=interface, prn=handle_packet)

if packets:
    wrpcap(traffic_file, packets)
    print(f"Traffic saved in {traffic_file}")
