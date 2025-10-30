from scapy.all import sniff, IP, UDP
import os
import wave
import threading
import sys
from collections import defaultdict

# Directory to save extracted payloads
os.makedirs("payloads", exist_ok=True)
os.makedirs("wav_files", exist_ok=True)

# Dictionary to store payloads grouped by source IP and port
payload_groups = defaultdict(bytearray)

def save_as_wav(payload, filename):
    with wave.open(filename, "wb") as wav_file:
        wav_file.setnchannels(1)  # Mono audio
        wav_file.setsampwidth(2)  # 16-bit samples
        wav_file.setframerate(8000)  # 8 kHz sample rate
        wav_file.writeframes(payload)

def detect_codec(payload):
    # Check for G.711 (PCMU or PCMA)
    if len(payload) > 0 and payload[0] in range(0x00, 0xFF):
        return "G.711"
    # Check for G.729 (simplified heuristic)
    elif len(payload) > 0 and len(payload) % 10 == 0:
        return "G.729"
    # Check for G.722
    elif len(payload) > 0 and payload[0] in range(0x65, 0x70):
        return "G.722"
    # Check for Opus
    elif len(payload) > 0 and payload[0] in range(0xF8, 0xFF):
        return "Opus"
    # Check for AMR
    elif len(payload) > 0 and payload[:4] == b"#!AMR":
        return "AMR"
    else:
        return "Unknown"

def process_packet(packet):
    if UDP in packet:
        src_ip = packet[IP].src
        src_port = packet[UDP].sport
        key = f"{src_ip}:{src_port}"

        print("UDP Packet Captured:")
        print(f"Source IP: {src_ip}, Source Port: {src_port}")
        print(f"Destination IP: {packet[IP].dst}, Destination Port: {packet[UDP].dport}")
        
        # Extract payload
        payload = bytes(packet[UDP].payload)
        print(f"Payload Length: {len(payload)} bytes")
        print(f"Payload Type: {type(payload)}")
        
        # Detect codec
        codec = detect_codec(payload)
        print(f"Detected Codec: {codec}")
        
        # Append payload to the group
        payload_groups[key].extend(payload)

def save_grouped_payloads():
    for key, payload in payload_groups.items():
        src_ip, src_port = key.split(":")
        
        # Save combined payload to binary file
        payload_filename = f"payloads/payload_{src_ip}_{src_port}.bin"
        with open(payload_filename, "wb") as f:
            f.write(payload)
        
        # Save combined payload to WAV file
        wav_filename = f"wav_files/audio_{src_ip}_{src_port}.wav"
        save_as_wav(payload, wav_filename)
        print(f"Saved combined WAV file: {wav_filename}")

# Start sniffing UDP packets
def start_sniffing():
    print("Starting UDP packet sniffing... Type 'quit' to exit.")
    sniff(filter="udp", prn=process_packet, stop_filter=lambda x: stop_sniffing)

def listen_for_quit():
    while True:
        user_input = input()
        if user_input.lower() == "quit":
            print("\nExiting gracefully...\n")
            global stop_sniffing
            stop_sniffing = True
            save_grouped_payloads()
            sys.exit(0)

# Global variable to stop sniffing
stop_sniffing = False

# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Listen for 'quit' command in the main thread
listen_for_quit()