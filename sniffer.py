import socket
socket.gethostbyaddr("142.250.202.36")
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

PCAP_FILE = "sniffer_capture.pcap"
captured_packets = []


# Function to process each packet
def packet_callback(packet):
    if IP in packet:  # Only analyze packets with an IP layer
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Map protocol number to name
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

        # Check for TCP/UDP to show ports
        if proto == 6 and TCP in packet:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {proto_name}")

        elif proto == 17 and UDP in packet:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {proto_name}")

        elif proto == 1 and ICMP in packet:  # ICMP
            print(f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {proto_name} (Ping)")

        else:
            print(f"[{timestamp}] {src_ip} -> {dst_ip} | Protocol: {proto_name}")

        captured_packets.append(packet)


def main():
    iface = None
    if len(sys.argv) > 1:
        iface = sys.argv[1]
        print(f"Using interface: {iface}")
    print("🚀 Advanced Sniffer started... Press Ctrl+C to stop.")
    try:
        # Start sniffing (only IP packets, show summary=False for clean output)
        sniff(filter="ip", prn=packet_callback, store=False, iface=iface)
    except PermissionError:
        print("❌ Permission denied. Please run as administrator/root.")
    except KeyboardInterrupt:
        print("\n🛑 Sniffer stopped by user.")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if captured_packets:
            wrpcap(PCAP_FILE, captured_packets)
            print(f"✅ Packets saved to {PCAP_FILE}")


if __name__ == "__main__":
    main()
