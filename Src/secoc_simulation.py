"""
Author: Aasai
Email: aasaialangaram450@gmail.com
Date: 2024-12-09
Description: This script simulates the SecOC CAN and Replay attack.
"""

import sys
import threading
import time
import hmac
import hashlib
import logging
import os
import datetime
import random
from queue import Queue
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QPushButton

# Secret key for MAC generation and verification (256-bit key)
SECRET_KEY = os.urandom(32)

# Simulated CAN bus as a shared queue
can_bus = Queue()

# Freshness manager to track FV
freshness_manager = set()

# Stop event to signal threads to stop
stop_event = threading.Event()


# Logging setup
def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')


def generate_mac(message, freshness, key):
    """Generate a MAC for a given message and freshness (timestamp)."""
    truncated_freshness = freshness & 0xFFFFFFFF 
    payload = f"{message}|{truncated_freshness}".encode()  
    mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return mac


def verify_mac(message, freshness, received_mac, key):
    """Verify the MAC for a given message and freshness (timestamp)."""
    truncated_freshness = freshness & 0xFFFFFFFF 
    calculated_mac = generate_mac(message, truncated_freshness, key)
    return hmac.compare_digest(calculated_mac, received_mac)


class ReceiverThread(QThread):
    new_message_signal = pyqtSignal(list, bool, str)

    def __init__(self):
        super().__init__()
        self.replay_attack_triggered = False  # Flag to ensure replay attack happens once

    def run(self):
        """Simulate a receiver ECU."""
        while not stop_event.is_set():  # Check the stop event to stop the thread
            if not can_bus.empty():
                payload = can_bus.get()
                parts = payload.split("|")
                if len(parts) == 5:
                    message_id, dlc, received_message, freshness, received_mac = parts
                    print('---', message_id, dlc, received_message, freshness, received_mac)
                    freshness = int(freshness)
                    dlc = int(dlc)

                    # Check if the DLC matches message length
                    if len(received_message.encode()) == dlc:
                        # Check if freshness is already used for replay attack detection
                        is_replay_attack = freshness in freshness_manager
                        logging.info(f"[Receiver] Freshness: {freshness}, Replay Attack: {is_replay_attack}")

                        if is_replay_attack:
                            if not self.replay_attack_triggered:
                                logging.warning(
                                    f"[Receiver] Replay attack detected! Freshness {freshness} already used.")
                                # Generate new freshness for retry
                                new_freshness = int(time.time()) + random.randint(0, 1000)  # Added randomness
                                mac = generate_mac(received_message, new_freshness, SECRET_KEY)
                                new_payload = f"{message_id}|{dlc}|{received_message}|{new_freshness}|{mac}"
                                can_bus.put(new_payload)  # Retry by pushing the message back to the CAN bus
                                self.new_message_signal.emit(parts, True, "Receiver")  # Mark as replay attack
                                self.replay_attack_triggered = True  # Flag to prevent further replay attacks
                        else:
                            # Verify the MAC if freshness is not reused
                            if verify_mac(received_message, freshness, received_mac, SECRET_KEY):
                                logging.info(
                                    f"[Receiver] Message authenticated: {received_message} (ID: {message_id}, "
                                    f"Freshness: {freshness})") 
                                freshness_manager.add(freshness)
                                self.new_message_signal.emit(parts, False, "Receiver")
                            else:
                                logging.warning(
                                    f"[Receiver] Authentication failed for message with freshness {freshness}. MACs "
                                    f"don't match.") 
            time.sleep(0.5)  


class SenderThread(QThread):
    last_sent_freshness = None  # Track the last sent freshness
    new_message_signal = pyqtSignal(list, bool, str)  # Signal for sending message

    def run(self):
        """Simulate a sender ECU."""
        message = "ECU1"
        message_id = 0x123  # CAN ID

        while not stop_event.is_set():  # Check the stop event to stop the thread
            # Generate freshness as the current timestamp for each message
            freshness = int(time.time()) + random.randint(0, 1000)  # Added randomness to the timestamp
            self.last_sent_freshness = freshness  # Store the last freshness
            mac = generate_mac(message, freshness, SECRET_KEY)
            dlc = len(message.encode())  # Data length in bytes
            payload = f"{message_id}|{dlc}|{message}|{freshness}|{mac}"
            can_bus.put(payload)
            logging.info(f"[Sender] Sent: {payload}")
            self.new_message_signal.emit([message_id, dlc, message, freshness, mac], False,
                                         "Sender")  # Send the message to UI
            time.sleep(1)  # Delay for simulation


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("CAN Message Simulation")
        self.setGeometry(100, 100, 800, 600)

        self.tableWidget = QTableWidget(self)
        self.tableWidget.setColumnCount(7)  # Added one more column for the message type (Sender/Receiver)
        self.tableWidget.setHorizontalHeaderLabels(
            ["Timestamp", "Message", "ID", "DLC", "Freshness", "MAC", "Type"])

        # Add Replay Attack Button
        self.replay_button = QPushButton('Trigger Replay Attack', self)
        self.replay_button.clicked.connect(self.trigger_replay_attack)

        # Add Start/Stop Simulation Button
        self.start_stop_button = QPushButton('Start Simulation', self)
        self.start_stop_button.clicked.connect(self.toggle_simulation)

        # Add Clear Simulation Button
        self.clear_button = QPushButton('Clear Simulation', self)
        self.clear_button.clicked.connect(self.clear_simulation)

        layout = QVBoxLayout()
        layout.addWidget(self.tableWidget)
        layout.addWidget(self.replay_button)
        layout.addWidget(self.start_stop_button)
        layout.addWidget(self.clear_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Create and start receiver and sender threads
        self.receiver_thread = ReceiverThread()
        self.receiver_thread.new_message_signal.connect(self.update_table)
        self.sender_thread = SenderThread()
        self.sender_thread.new_message_signal.connect(self.update_table)

        self.replay_attack_triggered = False  # Flag to ensure replay attack only happens once

    def update_table(self, message_parts, is_replay_attack, message_type):
        message_id, dlc, received_message, freshness, received_mac = message_parts
        # Get the current time
        current_time = datetime.datetime.now()
        formatted_time = current_time.strftime("%H:%M:%S")

        # Insert a new row in the table
        row_position = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_position)

        # Set table items
        self.tableWidget.setItem(row_position, 0, QTableWidgetItem(formatted_time))
        self.tableWidget.setItem(row_position, 1, QTableWidgetItem(received_message))
        self.tableWidget.setItem(row_position, 2, QTableWidgetItem(str(message_id)))
        self.tableWidget.setItem(row_position, 3, QTableWidgetItem(str(dlc)))
        self.tableWidget.setItem(row_position, 4, QTableWidgetItem(str(freshness)))
        self.tableWidget.setItem(row_position, 5, QTableWidgetItem(received_mac))
        self.tableWidget.setItem(row_position, 6, QTableWidgetItem(message_type))  # Set message type (Sender/Receiver)

        # If replay attack detected, set row color to red
        if is_replay_attack:
            for col in range(self.tableWidget.columnCount()):
                self.tableWidget.item(row_position, col).setBackground(Qt.red)

    def trigger_replay_attack(self):
        """Trigger the replay attack when the button is clicked."""
        if not self.replay_attack_triggered:
            logging.info("[Sender] Triggering replay attack.")
            # Trigger the replay attack with the last freshness value sent
            if self.sender_thread.last_sent_freshness:
                replay_freshness = self.sender_thread.last_sent_freshness
                message_id = 0x123
                message = "ECU1"
                dlc = len(message.encode())
                mac = generate_mac(message, replay_freshness, SECRET_KEY)
                payload = f"{message_id}|{dlc}|{message}|{replay_freshness}|{mac}"
                can_bus.put(payload)
                logging.info(f"[Sender] Sent replayed message: {payload}")
                self.replay_attack_triggered = True  # Set flag to prevent multiple attacks

    def toggle_simulation(self):
        """Start or stop the simulation."""
        if self.start_stop_button.text() == 'Start Simulation':
            # Start the threads
            stop_event.clear()  # Clear the stop event to allow threads to run
            self.receiver_thread.start()
            self.sender_thread.start()
            self.start_stop_button.setText('Stop Simulation')
            logging.info("Simulation started.")
        else:
            # Stop the threads
            stop_event.set()  # Set the stop event to signal threads to stop
            self.receiver_thread.wait()
            self.sender_thread.wait()
            self.start_stop_button.setText('Start Simulation')
            logging.info("Simulation stopped.")

    def clear_simulation(self):
        """Clear the simulation window for easier analysis"""
        # self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)

    def closeEvent(self, event):
        """Handle closing of the application."""
        stop_event.set()  # Set the stop event to stop the threads
        self.receiver_thread.wait()  # Wait for the receiver thread to finish
        self.sender_thread.wait()  # Wait for the sender thread to finish
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
