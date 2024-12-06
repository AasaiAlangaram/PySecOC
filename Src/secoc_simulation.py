import threading
import time
import hmac
import hashlib
import logging
import os
from queue import Queue

# Secret key for MAC generation and verification (initial secret key)
# Start with a 256-bit key
SECRET_KEY = os.urandom(32)  

# Simulated CAN bus as a shared queue
can_bus = Queue()

# Stop event to signal threads to terminate
stop_event = threading.Event()

# Freshness manager to track previously used freshness values
freshness_manager = set()


# Logging setup
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')


def rotate_key():
    """Rotate the MAC secret key periodically."""
    global SECRET_KEY
     # Generate a new 256-bit key
    SECRET_KEY = os.urandom(32) 
    logging.info("Key rotated.")


def get_truncated_freshness(freshness):
    """Truncate the freshness value to a shorter length (e.g., last 4 bytes). Truncate to the last 4 bytes (32 bits)"""
    return freshness & 0xFFFFFFFF  


def generate_mac(message, freshness, key):
    """Generate a MAC for a given message and freshness (timestamp)."""
    truncated_freshness = get_truncated_freshness(freshness)
    payload = f"{message}|{truncated_freshness}".encode()
    mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return mac


def verify_mac(message, freshness, received_mac, key):
    """Verify the MAC for a given message and freshness (timestamp)."""
    truncated_freshness = get_truncated_freshness(freshness)
    calculated_mac = generate_mac(message, truncated_freshness, key)
    return hmac.compare_digest(calculated_mac, received_mac)


def sender():
    """Simulate a sender ECU."""
    message = "EngineTemperature:85"
    message_id = 0x123  # CAN ID
    timestamp = int(time.time())  # Freshness as timestamp

    while not stop_event.is_set():
        mac = generate_mac(message, timestamp, SECRET_KEY)
        dlc = len(message.encode())  # Data length in bytes
        payload = f"{message_id}|{dlc}|{message}|{timestamp}|{mac}"
        can_bus.put(payload)  # Send the message to the CAN bus
        logging.info(f"[ECU 1] Sent: {payload}")

        # Periodically rotate the key for enhanced security & Rotate key every 60 seconds
        if int(time.time()) % 60 == 0:  
            rotate_key()

        # Delay 1s
        time.sleep(1) 


def receiver():
    """Simulate a receiver ECU."""
    # To track the last received freshness (timestamp)
    last_timestamp = 0  

    while not stop_event.is_set():
        if not can_bus.empty():
            # Receive the message from the CAN bus
            payload = can_bus.get()  
            logging.info(f"[ECU 2] Received: {payload}")

            parts = payload.split("|")
            if len(parts) == 5:
                message_id, dlc, received_message, freshness, received_mac = parts
                freshness = int(freshness)
                dlc = int(dlc)

                # Verify DLC matches message length
                if len(received_message.encode()) == dlc:
                    # Check for freshness (anti-replay)
                    if freshness not in freshness_manager:
                        if verify_mac(received_message, freshness, received_mac, SECRET_KEY):
                            logging.info(
                                f"[ECU 2] Message authenticated: {received_message} (ID: {message_id}, DLC: {dlc}, "
                                f"Freshness: {freshness})") 
                            freshness_manager.add(freshness)  
                        else:
                            logging.warning("[ECU 2] Authentication failed!")
                    else:
                        logging.warning(
                            f"[ECU 2] Replay attack detected! Freshness {freshness} already used. Last accepted "
                            f"freshness: {last_timestamp}. This message was received at "
                            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}.") 
                else:
                    logging.warning("[ECU 2] DLC mismatch!")
            else:
                logging.warning("[ECU 2] Malformed message received.")
        time.sleep(0.5)  


if __name__ == '__main__':
    setup_logging()

    # Start the sender and receiver threads
    stop_event.clear()

    sender_thread = threading.Thread(target=sender)
    receiver_thread = threading.Thread(target=receiver)

    sender_thread.start()
    receiver_thread.start()

    try:
        while True:
            time.sleep(1)  # Thread waits until sender and receiver are running
    except KeyboardInterrupt:
        stop_event.set()
        sender_thread.join()
        receiver_thread.join()
        logging.info("Simulation stopped.")
