import math
import json
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, Raw

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon entropy of a byte array.
    Returns a float between 0.0 (perfectly uniform) and 8.0 (perfectly random).
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    
    # Count the frequency of each byte (0-255)
    byte_counts = Counter(data)
    
    # Run the Shannon Entropy formula: H = -Sum(P(x) * log2(P(x)))
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def process_packet(packet):
    """
    Callback function executed for every packet captured.
    Strips headers, calculates entropy of the payload, and outputs JSON.
    """
    # We only care about packets that have a Raw payload and an IP header
    if packet.haslayer(Raw) and packet.haslayer(IP):
        payload = packet[Raw].load
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Extract protocol and ports
        protocol = "UNKNOWN"
        src_port = 0
        dst_port = 0
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return # Skip if not TCP or UDP

        # Calculate the mathematical randomness of the payload
        entropy_score = calculate_shannon_entropy(payload)

        # Flag high entropy traffic (typically encrypted or compressed data)
        # 7.5+ is a common threshold for highly randomized data
        status_flag = "🔴 ENCRYPTED/ANOMALY" if entropy_score > 7.5 else "🔵 PLAINTEXT"

        # Format as a dictionary ready to be streamed to a frontend via WebSockets
        packet_data = {
            "source": f"{ip_src}:{src_port}",
            "destination": f"{ip_dst}:{dst_port}",
            "protocol": protocol,
            "payload_bytes": len(payload),
            "entropy": round(entropy_score, 3),
            "status": status_flag
        }

        # For this prototype, we print it to the console. 
        # In a full build, you would do: websocket.send(json.dumps(packet_data))
        print(f"[{protocol}] Port {dst_port:<5} | Size: {len(payload):<4} | Entropy: {packet_data['entropy']:<5.3f} | {status_flag}")

if __name__ == "__main__":
    print("Starting Packet Entropy Analyzer...")
    print("Listening for traffic (Press Ctrl+C to stop)...\n")
    
    try:
        # Start sniffing the default network interface
        # store=False ensures we don't hold packets in memory and crash the system
        sniff(prn=process_packet, store=False, filter="ip")
    except PermissionError:
        print("ERROR: Packet sniffing requires root/administrator privileges.")
        print("Run this script using 'sudo python3 entropy_sniffer.py' on Linux/Mac, or run as Admin on Windows.")