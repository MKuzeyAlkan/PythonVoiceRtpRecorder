from scapy.all import sniff, RTP, IP, UDP
import os
import wave
import threading
import sys

# Directory to save extracted payloads
os.makedirs("payloads", exist_ok=True)
os.makedirs("wav_files", exist_ok=True)

def save_as_wav(payload, filename):
    with wave.open(filename, "wb") as wav_file:
        wav_file.setnchannels(1)  # Mono audio
        wav_file.setsampwidth(2)  # 16-bit samples
        wav_file.setframerate(8000)  # 8 kHz sample rate
        wav_file.writeframes(payload)

def process_packet(packet):
    if RTP in packet:
        print("RTP Packet Captured:")
        print(f"Source IP: {packet[IP].src}, Source Port: {packet[UDP].sport}")
        print(f"Destination IP: {packet[IP].dst}, Destination Port: {packet[UDP].dport}")
        
        # Extract payload
        payload = bytes(packet[RTP].load)
        print(f"Payload Length: {len(payload)} bytes")
        
        # Save payload to binary file
        payload_filename = f"payloads/payload_{packet.time}.bin"
        with open(payload_filename, "wb") as f:
            f.write(payload)
        
        # Convert payload to WAV
        wav_filename = f"wav_files/audio_{packet.time}.wav"
        save_as_wav(payload, wav_filename)
        print(f"Saved WAV file: {wav_filename}")

def start_sniffing():
    print("Starting RTP packet sniffing... Type 'quit' to exit.")
    sniff(filter="udp", prn=process_packet, stop_filter=lambda x: stop_sniffing)

def listen_for_quit():
    while True:
        user_input = input()
        if user_input.lower() == "quit":
            print("\nExiting gracefully...\n")
            global stop_sniffing
            stop_sniffing = True
            sys.exit(0)

# Global variable to stop sniffing
stop_sniffing = False

# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Listen for 'quit' command in the main thread
listen_for_quit()