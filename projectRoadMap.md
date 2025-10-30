# Project Roadmap: Voice Recording With RTP Sessions

## Project Overview
This project aims to develop a Python application that listens to RTP packets over VoIP and records audio. The application will not use a microphone or any other input device. Instead, it will capture RTP packets and save them in a playable `.wav` format. Additionally, it will log essential packet information and SIP session details in `.txt` files.

## Features
1. **RTP Packet Capture**
   - Capture RTP packets from VoIP sessions.
   - Save audio data in `.wav` format.

2. **Packet Information Logging**
   - Log basic RTP packet details (e.g., IP, port) into a `.txt` file.

3. **SIP Session Logging**
   - Extract and log all SIP packet information related to the RTP session into a `.txt` file.

## Proposed Enhancements
*The following enhancements are deferred and will not be implemented in the initial phase:*
- **Real-time Playback (Optional):** Allow real-time playback of the captured audio.
- **Session Filtering:** Provide options to filter sessions based on IP, port, or other criteria.
- **Error Handling:** Implement robust error handling for packet loss, malformed packets, etc.
- **Performance Optimization:** Optimize for high traffic scenarios to ensure no packet loss.
- **GUI (Optional):** Develop a graphical user interface for easier interaction.

## Implementation Plan
### Phase 1: Research and Setup
- Research libraries for packet capture (e.g., `scapy`, `pyshark`).
- Research libraries for audio processing (e.g., `pydub`, `wave`).
- Set up the development environment.

### Phase 2: RTP Packet Capture
- Implement RTP packet sniffing.
- Extract audio payload from RTP packets.
- Save audio payload as `.wav`.

### Phase 3: Logging *(Deferred)*
*This phase will be implemented later.*
- Parse RTP packets to extract IP, port, and other details.
- Log these details into a `.txt` file.
- Parse SIP packets to extract session details.
- Log SIP session details into a `.txt` file.

### Phase 4: Testing *(Deferred)*
*This phase will be implemented later.*
- Test with sample RTP and SIP packets.
- Validate `.wav` file playback.
- Validate `.txt` file contents.

### Phase 5: Enhancements (Optional) *(Deferred)*
*This phase will be implemented later.*
- Implement real-time playback.
- Add session filtering options.
- Optimize performance for high traffic scenarios.
- Develop a GUI (if required).

## Deliverables
1. A Python script to capture and save RTP packets as `.wav` files.
2. A `.txt` file logging RTP packet details.
3. A `.txt` file logging SIP session details.
4. Documentation on how to use the application.

## Tools and Libraries
- **Packet Capture:** `scapy`, `pyshark`
- **Audio Processing:** `pydub`, `wave`
- **Logging:** Python's built-in `logging` module

## Timeline
- **Week 1:** Research and setup
- **Week 2:** Implement RTP packet capture
- **Week 3:** Implement logging *(Deferred)*
- **Week 4:** Testing and validation *(Deferred)*
- **Week 5:** Optional enhancements *(Deferred)*

---

Feel free to suggest additional features or modifications to the roadmap!