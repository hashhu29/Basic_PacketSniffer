from scapy.all import sniff

def process_packets(packet):
    print(packet.summary()) #prints summary of a packet

print("started.")
sniff(prn=process_packets, count=8) # captures 8 packets and passes them to "process_packet"

#filtering
sniff(prn=process_packets, filter = "TCP Port 80", count=5)


