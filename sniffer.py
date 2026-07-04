from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP
import threading
import datetime
import time
import requests
import socket
from collections import defaultdict

app = Flask(__name__)
CORS(app)

packets_data = []
packet_id = 1

# Naya variable: Sniffer ko Start/Stop control karne ke liye
is_sniffing = True 

ip_tracker = defaultdict(int)
last_clear_time = time.time()
location_cache = {}
domain_cache = {}

def get_ip_location(ip):
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return "Local 🏠"
    if ip in location_cache:
        return location_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response["status"] == "success":
            location = f"{response['country']} ({response['countryCode']})"
            location_cache[ip] = location
            return location
    except:
        pass
    location_cache[ip] = "Unknown 🌍"
    return "Unknown 🌍"

def get_domain_name(ip):
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return "Local Device"
    if ip in domain_cache:
        return domain_cache[ip]
    try:
        host_name = socket.gethostbyaddr(ip)[0]
        domain_cache[ip] = host_name
        return host_name
    except:
        domain_cache[ip] = "Unknown Host"
        return "Unknown Host"

def process_packet(packet):
    global packet_id, last_clear_time, is_sniffing
    
    # Agar frontend se STOP dabaya gaya hai, toh packet ignore kar do
    if not is_sniffing:
        return
        
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "IP"
            
        length = len(packet)
        current_time_str = datetime.datetime.now().strftime("%H:%M:%S")
        
        current_time_sec = time.time()
        if current_time_sec - last_clear_time > 5:
            ip_tracker.clear()
            last_clear_time = current_time_sec
            
        ip_tracker[src_ip] += 1
        is_threat = True if ip_tracker[src_ip] > 10 else False
        
        dst_location = get_ip_location(dst_ip)
        dst_domain = get_domain_name(dst_ip)
        
        pkt_info = {
            "id": packet_id,
            "time": current_time_str,
            "src": src_ip,
            "dst": dst_ip,
            "domain": dst_domain,
            "protocol": protocol,
            "length": length,
            "is_threat": is_threat,
            "location": dst_location
        }
        
        if len(packets_data) >= 15:
            packets_data.pop(0)
            
        packets_data.append(pkt_info)
        packet_id += 1

def start_sniffing():
    print("Sniffer with DNS Resolution & Geo-Location started...")
    sniff(prn=process_packet, store=False)

# --- NAYE ENDPOINTS BUTTONS KE LIYE ---
@app.route('/api/packets', methods=['GET'])
def get_packets():
    return jsonify(packets_data)

@app.route('/api/toggle', methods=['POST'])
def toggle_sniffing():
    global is_sniffing
    is_sniffing = not is_sniffing
    return jsonify({"status": "success", "is_sniffing": is_sniffing})

@app.route('/api/clear', methods=['POST'])
def clear_data():
    global packets_data, packet_id
    packets_data.clear()
    packet_id = 1  # ID wapas 1 se start hogi
    return jsonify({"status": "success"})
# --------------------------------------

if __name__ == '__main__':
    socket.setdefaulttimeout(0.5) 
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    print("Backend API running on http://127.0.0.1:5000")
    app.run(port=5000)