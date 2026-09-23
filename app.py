import math
from collections import Counter
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR


app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key' 
socketio = SocketIO(app, cors_allowed_origins="*")

def calculate_shannon_entropy(data: bytes) -> float:
    
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    byte_counts = Counter(data)
    
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def process_packet(packet):
    
    if packet.haslayer(Raw) and packet.haslayer(IP):
        payload = packet[Raw].load
        protocol = "UNKNOWN"
        dst_port = 0
        src_port = 0
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport 
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dst_port = packet[UDP].dport
            src_port = packet[UDP].sport 
        else:
            return

        
        entropy_score = calculate_shannon_entropy(payload)

       
        packet_data = {
            "port": dst_port,
            "src_port": src_port,  
            "protocol": protocol,
            "size": len(payload),
            "entropy": round(entropy_score, 3)
        }

       
        socketio.emit('packet_stream', packet_data)

def start_sniffer():
    
    print("[*] Scapy sniffer started. Capturing packets...")
    sniff(prn=process_packet, store=False, filter="ip")



@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print("[*] Browser frontend connected to WebSocket stream.")

@socketio.on('disconnect')
def handle_disconnect():
    print("[*] Browser frontend disconnected.")

if __name__ == '__main__':
   
    socketio.start_background_task(start_sniffer)
    
    
    print("[*] Starting Flask server on http://localhost:5001")
    socketio.run(app, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)