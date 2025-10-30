# Packet Capture Libraries Research

## Scapy
Scapy is a powerful Python library used for packet manipulation and analysis. It allows you to capture, decode, and analyze network packets. It is highly flexible and supports custom packet crafting.

### Features:
- Packet sniffing and sending.
- Protocol dissection and analysis.
- Support for various protocols, including RTP.
- Easy-to-use API for packet manipulation.

### Pros:
- Highly customizable.
- Active community support.
- No external dependencies.

### Cons:
- May require deeper networking knowledge.
- Performance may degrade with high traffic.

### Installation:
```bash
pip install scapy
```

## Pyshark
Pyshark is a Python wrapper for the Wireshark packet capture tool. It provides an easy way to capture and analyze packets using the tshark utility.

### Features:
- Live packet capture.
- File-based packet analysis (e.g., pcap files).
- Support for RTP and SIP protocols.
- High-level API for filtering and dissecting packets.

### Pros:
- Leverages Wireshark's powerful dissection capabilities.
- Easy to use for common packet analysis tasks.
- Well-documented.

### Cons:
- Requires Wireshark/tshark to be installed.
- Limited customization compared to Scapy.

### Installation:
```bash
pip install pyshark
```

## Recommendation
For this project, both libraries are suitable. However, the choice depends on the specific requirements:
- Use **Scapy** if you need full control over packet manipulation and crafting.
- Use **Pyshark** if you prefer leveraging Wireshark's dissection capabilities and need a simpler setup for packet analysis.