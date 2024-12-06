# SecOC (Secure On-Board Communication) Simulation

This is a Python-based simulation of the **Secure On-Board Communication (SecOC)** protocol, which is designed to ensure secure communication within an ECU network, such as for automotive applications. This simulation mimics two ECUs (Electronic Control Units) that send and receive messages over a simulated CAN bus while implementing basic security features such as Message Authentication Code (MAC) and freshness checks to prevent replay attacks.

## Features
- **Message Authentication**: Uses HMAC with SHA256 to ensure message integrity and authenticity.
- **Replay Attack Detection**: Implements freshness timestamps to detect replay attacks based on stale message freshness.
- **Key Rotation**: Periodically rotates the secret key used to generate MACs to enhance security.
- **CAN Bus Simulation**: Simulates the transmission of messages between sender and receiver ECUs over a queue that mimics a CAN bus.
- **Logging**: Displays simulation logs in the console to track the communication and security checks (e.g., successful authentication, replay attacks).
  
## Requirements
- Python 3.6 or higher
- PyQt5 (for UI in case of GUI implementation, but can be removed if not needed)
- `queue` (Python standard library)

To install required dependencies, you can use `pip`:

```bash
pip install pyqt5
