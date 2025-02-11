#!/usr/bin/env python3
"""
Advanced Cybersecurity Suite
----------------------------
This proof‐of‐concept tool integrates a wide range of cybersecurity functions to
demonstrate how modern AI‑assisted and automated techniques can help keep networks safe.
It includes:
  • Passive monitoring (SYN scan detection, basic DPI)
  • Active scanning using Nmap
  • Machine Learning anomaly detection (Isolation Forest) plus a stub for deep learning models
  • Threat Intelligence lookups (stubbed for AbuseIPDB and multi‑feed integration)
  • Automated incident response (blocking IPs via iptables, dynamic firewall adjustments)
  • Forensic capabilities (saving PCAP files for suspicious events)
  • Distributed sensor integration stub (e.g. sending alerts to a message broker)
  • RESTful API endpoints (via Flask) for external integration and ChatOps queries
  • An interactive CLI menu and a feature‐rich GUI (with login, real‑time logs, tables, and graphs)
  • **NEW!** SSH brute force module (using Paramiko)
  • **NEW!** WiFi scanning (using system “nmcli” command)
  • **NEW!** ARP network mapping (using “arp-scan” command stub)

Before running:
  • Install dependencies with: pip install -r requirements.txt
  • Ensure Nmap is installed and in your PATH.
  • On Linux, some features (e.g. iptables blocking, nmcli, arp-scan) require appropriate privileges.
  • Use these features only on networks where you have permission.

Default GUI login credentials: username: "admin" / password: "password"
"""

import sys
import time
import threading
import argparse
import logging
import subprocess
import json
from collections import defaultdict, deque

# Scapy for packet capture
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap

# Machine Learning libraries
import numpy as np
from sklearn.ensemble import IsolationForest

# For threat intelligence lookups
import requests

# Flask for REST API
from flask import Flask, jsonify, request

# PyQt5 and PyQtGraph for GUI
from PyQt5.QtCore import pyqtSignal, QObject, QTimer, Qt
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QSplitter,
    QLineEdit,
    QLabel,
    QDialog,
    QDialogButtonBox,
    QFormLayout
)
import pyqtgraph as pg

# --- Additional Module: Paramiko for SSH Brute Forcing ---
import paramiko

# ----------------------- Command-line Arguments -----------------------
parser = argparse.ArgumentParser(
    description="Advanced Cybersecurity Suite"
)
parser.add_argument("--threshold", type=int, default=10, help="SYN packet count threshold")
parser.add_argument("--time_window", type=int, default=60, help="Time window (seconds)")
parser.add_argument("--alert_cooldown", type=int, default=300, help="Cooldown period (seconds) for alerts")
parser.add_argument("--ti_api_key", type=str, default="", help="Threat Intelligence API Key")
args, unknown = parser.parse_known_args()

THRESHOLD = args.threshold
TIME_WINDOW = args.time_window
ALERT_COOLDOWN = args.alert_cooldown
TI_API_KEY = args.ti_api_key

# ----------------------- Logging Setup -----------------------
logger = logging.getLogger("advanced_cyber_detector")
logger.setLevel(logging.INFO)
from logging.handlers import RotatingFileHandler

file_handler = RotatingFileHandler("advanced_syn_alerts.log", maxBytes=5 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# ----------------------- Global Data Structures -----------------------
timestamps = defaultdict(deque)  # {ip: deque([timestamps])}
alerted_ips = {}  # {ip: last_alert_timestamp}
scanned_ips = {}  # {ip: last_scan_timestamp}
api_alerts = []  # List of alerts for API exposure
ml_data = []  # Data for ML anomaly detection
pcap_storage = defaultdict(list)  # {ip: list of packets} for forensic purposes

# Thread safety lock
lock = threading.Lock()

# ----------------------- Flask API Setup -----------------------
app = Flask(__name__)


# ----------------------- Machine Learning Setup -----------------------
def initialize_ml_model():
    """
    Initialize an Isolation Forest for anomaly detection.
    In production, use historical training data.
    """
    global ml_model
    ml_model = IsolationForest(contamination=0.05)
    dummy_data = np.random.rand(100, 1)  # Dummy training data
    ml_model.fit(dummy_data)


initialize_ml_model()


def ml_detect_anomaly(value):
    """
    Use the ML model to determine if the given value is anomalous.
    Returns True if anomalous.
    """
    global ml_model
    prediction = ml_model.predict(np.array([[value]]))
    return prediction[0] == -1  # -1 indicates anomaly


def deep_learning_anomaly_detection(value):
    """
    Stub for deep learning–based anomaly detection.
    Replace with your TensorFlow/PyTorch model.
    """
    logger.info("Deep learning anomaly detection stub called.")
    return False


# ----------------------- Threat Intelligence & Incident Response -----------------------
def threat_intelligence_lookup(ip):
    """
    Query a threat intelligence feed for the given IP.
    Stub for AbuseIPDB. Extend to multiple feeds.
    """
    if not TI_API_KEY:
        return "No Threat Intelligence API key provided."
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Accept": "application/json", "Key": TI_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return f"TI lookup error: {response.status_code}"
    except Exception as e:
        return str(e)


def threat_intelligence_lookup_multiple(ip):
    """
    Stub to integrate multiple threat intelligence feeds.
    """
    ti1 = threat_intelligence_lookup(ip)
    combined_info = {"AbuseIPDB": ti1, "OtherFeed": "Data not implemented"}
    return combined_info


def automated_incident_response(ip):
    """
    Block the offending IP using iptables (Linux).
    Ensure the script is run with appropriate privileges.
    """
    try:
        command = f"sudo iptables -A INPUT -s {ip} -j DROP"
        subprocess.check_output(command, shell=True)
        logger.info(f"Automated Response: Blocked IP {ip}")
    except Exception as e:
        logger.error(f"Failed to block IP {ip}: {e}")


def dynamic_firewall_adjustment(ip, action="block"):
    """
    Stub for dynamic firewall adjustments.
    """
    logger.info(f"Dynamic firewall adjustment: {action} IP {ip}")
    # Insert system-specific commands or API calls here.


# ----------------------- Distributed Sensor Integration -----------------------
def send_to_message_broker(data):
    """
    Stub to send data to a message broker (e.g., RabbitMQ, Kafka).
    """
    logger.info(f"Sending data to message broker: {data}")


# ----------------------- Forensic Capabilities -----------------------
def save_pcap_for_alert(ip):
    """
    Save packets for a given IP to a PCAP file for forensic analysis.
    """
    with lock:
        packets = pcap_storage.get(ip, [])
        if packets:
            filename = f"forensics_{ip.replace('.', '_')}_{int(time.time())}.pcap"
            wrpcap(filename, packets)
            logger.info(f"Saved PCAP for IP {ip} to {filename}")
        else:
            logger.info(f"No packets available for IP {ip} to save.")


# ----------------------- ChatOps / AI Chatbot Integration -----------------------
def chatops_integration(query):
    """
    Stub for ChatOps/AI chatbot integration.
    """
    response = f"ChatOps stub response for query: {query}"
    logger.info(response)
    return response


# ----------------------- Active Scanning -----------------------
def run_nmap_scan(target):
    """
    Execute an Nmap scan on the target.
    Returns the output.
    """
    try:
        output = subprocess.check_output(["nmap", "-A", target], stderr=subprocess.STDOUT, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error running nmap on {target}:\n{e.output}"


# ----------------------- Advanced Modules: Brute Forcing, WiFi & ARP Scanning -----------------------
def brute_force_ssh(target, username, password_file):
    """
    Attempts to brute force SSH credentials on the target.
    Use only in controlled environments with permission.
    """
    try:
        with open(password_file, 'r') as f:
            passwords = f.read().splitlines()
    except Exception as e:
        print(f"Error reading password file: {e}")
        return None

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in passwords:
        try:
            ssh.connect(target, username=username, password=password, timeout=5)
            print(f"Success: {target} - {username}:{password}")
            ssh.close()
            return password
        except Exception:
            continue
    print("Brute force failed: No valid credentials found.")
    return None


def scan_wifi_networks():
    """
    Scans for available WiFi networks using the 'nmcli' command (Linux).
    Returns the scan results.
    """
    try:
        output = subprocess.check_output(["nmcli", "device", "wifi", "list"], text=True)
        return output
    except Exception as e:
        return f"Error scanning WiFi networks: {e}"


def arp_scan_network():
    """
    Scans the local network using 'arp-scan'.
    Note: arp-scan must be installed and may require root privileges.
    """
    try:
        output = subprocess.check_output(["arp-scan", "-l"], text=True)
        return output
    except Exception as e:
        return f"Error scanning network with arp-scan: {e}"


# ----------------------- Packet Processing & DPI -----------------------
def packet_callback(packet):
    """
    Process each captured packet.
    - Save packets for forensic analysis.
    - Process TCP SYN packets.
    - Basic DPI: HTTP, DNS.
    """
    # Save packet for forensic purposes.
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        with lock:
            pcap_storage[src_ip].append(packet)

    # Process TCP SYN packets.
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if (tcp_layer.flags & 0x02) and not (tcp_layer.flags & 0x10):
            process_syn_packet(packet)

    # DPI: Detect HTTP traffic (simplified).
    if packet.haslayer(TCP) and packet.haslayer(IP):
        payload = bytes(packet[TCP].payload)
        if b"HTTP" in payload:
            logger.info(f"DPI: HTTP traffic detected from {packet[IP].src}")

    # DPI: Detect DNS traffic.
    if packet.haslayer(UDP) and packet.haslayer(IP):
        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            logger.info(f"DPI: DNS traffic detected from {packet[IP].src}")


def process_syn_packet(packet):
    """
    Process a SYN-only packet: update counts, run ML checks,
    trigger active scans and incident responses.
    """
    src_ip = packet[IP].src
    current_time = time.time()
    with lock:
        while timestamps[src_ip] and timestamps[src_ip][0] < current_time - TIME_WINDOW:
            timestamps[src_ip].popleft()
        timestamps[src_ip].append(current_time)
        count = len(timestamps[src_ip])
        ml_data.append(count)

    if ml_detect_anomaly(count):
        logger.info(f"ML Anomaly Detected (Isolation Forest): {src_ip} count {count}")
    if deep_learning_anomaly_detection(count):
        logger.info(f"ML Anomaly Detected (Deep Learning): {src_ip} count {count}")

    with lock:
        last_alert_time = alerted_ips.get(src_ip, 0)
    if count >= THRESHOLD and (current_time - last_alert_time > ALERT_COOLDOWN):
        alert_msg = f"[ALERT] Potential scanning from {src_ip} (SYN Count: {count})"
        logger.info(alert_msg)
        with lock:
            alerted_ips[src_ip] = current_time
            api_alerts.append({"ip": src_ip, "count": count, "timestamp": current_time})
        ti_info = threat_intelligence_lookup_multiple(src_ip)
        logger.info(f"Threat Intelligence for {src_ip}: {ti_info}")
        threading.Thread(target=automated_incident_response, args=(src_ip,), daemon=True).start()
        save_pcap_for_alert(src_ip)
        send_to_message_broker({"ip": src_ip, "alert": alert_msg})
        with lock:
            last_scan_time = scanned_ips.get(src_ip, 0)
        if current_time - last_scan_time > ALERT_COOLDOWN:
            with lock:
                scanned_ips[src_ip] = current_time
            threading.Thread(target=lambda: logger.info(run_nmap_scan(src_ip)), daemon=True).start()


def cleanup_old_entries():
    """
    Periodically remove expired entries from tracking dictionaries.
    """
    while True:
        time.sleep(TIME_WINDOW)
        current_time = time.time()
        with lock:
            for ip in list(timestamps.keys()):
                while timestamps[ip] and timestamps[ip][0] < current_time - TIME_WINDOW:
                    timestamps[ip].popleft()
                if not timestamps[ip]:
                    del timestamps[ip]


# ----------------------- Sniffer Thread -----------------------
class SnifferThread(threading.Thread):
    """
    A dedicated thread to run Scapy’s sniffer.
    """

    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()
        self.daemon = True

    def run(self):
        sniff(filter="ip", prn=packet_callback, store=False, stop_filter=self.should_stop)

    def should_stop(self, packet):
        return self._stop_event.is_set()

    def stop(self):
        self._stop_event.set()


# ----------------------- Flask API Endpoints -----------------------
@app.route("/alerts", methods=["GET"])
def get_alerts():
    """
    Return a JSON list of detected alerts.
    """
    with lock:
        return jsonify(api_alerts)


@app.route("/scan", methods=["POST"])
def trigger_scan():
    """
    Trigger an active Nmap scan via API.
    Example POST JSON: {"target": "192.168.1.1"}
    """
    data = request.json
    target = data.get("target")
    if target:
        result = run_nmap_scan(target)
        return jsonify({"target": target, "result": result})
    else:
        return jsonify({"error": "No target specified"}), 400


@app.route("/chatops", methods=["POST"])
def chatops_query():
    """
    Process a ChatOps query via API.
    Example POST JSON: {"query": "What is the system status?"}
    """
    data = request.json
    query = data.get("query")
    if query:
        response = chatops_integration(query)
        return jsonify({"response": response})
    else:
        return jsonify({"error": "No query provided"}), 400


def start_api_server():
    """
    Launch the Flask API server on a separate thread.
    """
    app.run(port=5000)


# ----------------------- GUI Components -----------------------
# --- Login Dialog for Role-Based Access (Stub) ---
class LoginDialog(QDialog):
    """
    A simple login dialog.
    Username: admin, Password: password
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.resize(300, 100)
        layout = QFormLayout(self)
        self.username_input = QLineEdit(self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Username:", self.username_input)
        layout.addRow("Password:", self.password_input)
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def accept(self):
        if self.username_input.text() == "admin" and self.password_input.text() == "password":
            super().accept()
        else:
            self.username_input.clear()
            self.password_input.clear()
            self.setWindowTitle("Login Failed! Try Again.")


# --- GUI Logging Handler ---
class GuiLogHandler(QObject, logging.Handler):
    """
    Custom logging handler to send log messages to the GUI.
    """
    new_log = pyqtSignal(str)

    def __init__(self):
        QObject.__init__(self)
        logging.Handler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.new_log.emit(msg)


# --- Scan Result Dialog ---
class ScanResultDialog(QDialog):
    """
    Dialog to display Nmap scan results.
    """

    def __init__(self, title, scan_result, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(600, 400)
        layout = QVBoxLayout()
        self.result_edit = QPlainTextEdit()
        self.result_edit.setPlainText(scan_result)
        self.result_edit.setReadOnly(True)
        layout.addWidget(self.result_edit)
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)
        self.setLayout(layout)


# --- Main Window ---
class MainWindow(QMainWindow):
    """
    Main GUI window with real-time logs, a table of top SYN senders, and a dynamic graph.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Cybersecurity Suite")
        self.resize(1200, 800)
        self.sniffer_thread = None

        # Start/Stop monitoring buttons
        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)

        # Manual Nmap scan controls
        self.range_label = QLabel("Nmap Scan:")
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("Enter IP or range (e.g., 192.168.1.0/24)")
        self.range_scan_button = QPushButton("Scan")
        self.range_scan_button.clicked.connect(self.start_range_scan)
        manual_scan_layout = QHBoxLayout()
        manual_scan_layout.addWidget(self.range_label)
        manual_scan_layout.addWidget(self.range_input)
        manual_scan_layout.addWidget(self.range_scan_button)

        # Log display
        self.log_text_edit = QPlainTextEdit()
        self.log_text_edit.setReadOnly(True)

        # Table for top SYN senders
        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(2)
        self.table_widget.setHorizontalHeaderLabels(["IP Address", "SYN Count"])

        # Real-time graph using PyQtGraph
        self.graph_widget = pg.PlotWidget(title="Real-time SYN Count")
        self.graph_widget.setLabel('left', 'SYN Count')
        self.graph_widget.setLabel('bottom', 'Time (s)')
        self.graph_curve = self.graph_widget.plot(pen='y')
        self.graph_data = []
        self.graph_timestamps = []

        # Splitter to arrange panels
        splitter = QSplitter()
        log_container = QWidget()
        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_text_edit)
        log_container.setLayout(log_layout)

        table_container = QWidget()
        table_layout = QVBoxLayout()
        table_layout.addWidget(self.table_widget)
        table_container.setLayout(table_layout)

        graph_container = QWidget()
        graph_layout = QVBoxLayout()
        graph_layout.addWidget(self.graph_widget)
        graph_container.setLayout(graph_layout)

        splitter.addWidget(log_container)
        splitter.addWidget(table_container)
        splitter.addWidget(graph_container)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setStretchFactor(2, 2)

        # Main layout
        main_layout = QVBoxLayout()
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_button)
        btn_layout.addWidget(self.stop_button)
        main_layout.addLayout(btn_layout)
        main_layout.addLayout(manual_scan_layout)
        main_layout.addWidget(splitter)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # GUI logging integration
        self.gui_log_handler = GuiLogHandler()
        self.gui_log_handler.setFormatter(formatter)
        self.gui_log_handler.new_log.connect(self.append_log)
        logging.getLogger("advanced_cyber_detector").addHandler(self.gui_log_handler)

        # Timer to update UI every second
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)

    def append_log(self, msg):
        self.log_text_edit.appendPlainText(msg)

    def update_ui(self):
        # Update top SYN senders table
        with lock:
            top_senders = sorted(
                ((ip, len(deq)) for ip, deq in timestamps.items()),
                key=lambda x: x[1], reverse=True
            )[:5]
        self.table_widget.setRowCount(len(top_senders))
        for row, (ip, count) in enumerate(top_senders):
            ip_item = QTableWidgetItem(ip)
            count_item = QTableWidgetItem(str(count))
            ip_item.setTextAlignment(Qt.AlignCenter)
            count_item.setTextAlignment(Qt.AlignCenter)
            self.table_widget.setItem(row, 0, ip_item)
            self.table_widget.setItem(row, 1, count_item)

        # Update real-time graph
        current_time = time.time()
        total_syn_count = sum(len(deq) for deq in timestamps.values())
        self.graph_timestamps.append(current_time)
        self.graph_data.append(total_syn_count)
        while self.graph_timestamps and current_time - self.graph_timestamps[0] > 60:
            self.graph_timestamps.pop(0)
            self.graph_data.pop(0)
        self.graph_curve.setData(self.graph_timestamps, self.graph_data)

    def start_monitoring(self):
        if not self.sniffer_thread:
            self.sniffer_thread = SnifferThread()
            self.sniffer_thread.start()
            logger.info("Monitoring started.")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

    def stop_monitoring(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.join()
            self.sniffer_thread = None
            logger.info("Monitoring stopped.")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def start_range_scan(self):
        target = self.range_input.text().strip()
        if not target:
            self.append_log("Please enter a valid target.")
            return
        self.append_log(f"Starting Nmap scan on {target}...")
        threading.Thread(target=lambda: self.run_nmap_and_show(target), daemon=True).start()

    def run_nmap_and_show(self, target):
        result = run_nmap_scan(target)
        dlg = ScanResultDialog(f"Nmap Scan: {target}", result, self)
        dlg.exec_()


# ----------------------- Interactive CLI Menu -----------------------
def interactive_menu():
    """
    Interactive CLI menu with extended advanced options.
    Options:
      1. Start passive monitoring (GUI mode)
      2. Run a manual Nmap scan
      3. Perform a Threat Intelligence lookup on an IP
      4. Execute automated incident response (block an IP)
      5. ChatOps query
      6. SSH brute force attack (penetration testing)
      7. Scan available WiFi networks
      8. ARP network mapping scan
      9. Exit
    """
    print("Welcome to the Advanced Cybersecurity Suite!")
    while True:
        print("\nPlease choose an option:")
        print("1. Start passive monitoring (GUI mode)")
        print("2. Run a manual Nmap scan")
        print("3. Perform a Threat Intelligence lookup on an IP")
        print("4. Execute automated incident response (block an IP)")
        print("5. ChatOps query")
        print("6. SSH brute force attack (penetration testing)")
        print("7. Scan available WiFi networks")
        print("8. ARP network mapping scan")
        print("9. Exit")
        choice = input("Enter your choice (1-9): ").strip()
        if choice == "1":
            return "gui"
        elif choice == "2":
            target = input("Enter the target IP or range for Nmap scan: ").strip()
            print(f"Starting Nmap scan on {target}...")
            result = run_nmap_scan(target)
            print("Nmap scan results:")
            print(result)
        elif choice == "3":
            ip = input("Enter the IP for threat intelligence lookup: ").strip()
            print(f"Performing threat intelligence lookup for {ip}...")
            ti_result = threat_intelligence_lookup_multiple(ip)
            print("Threat intelligence result:")
            print(json.dumps(ti_result, indent=2))
        elif choice == "4":
            ip = input("Enter the IP to block: ").strip()
            print(f"Attempting to block IP {ip}...")
            automated_incident_response(ip)
            print("Incident response executed (check logs for details).")
        elif choice == "5":
            query = input("Enter your ChatOps query: ").strip()
            response = chatops_integration(query)
            print("ChatOps response:")
            print(response)
        elif choice == "6":
            target = input("Enter the target IP for SSH brute force: ").strip()
            username = input("Enter the username: ").strip()
            password_file = input("Enter the path to the password file: ").strip()
            brute_force_ssh(target, username, password_file)
        elif choice == "7":
            print("Scanning for WiFi networks...")
            wifi_results = scan_wifi_networks()
            print("WiFi scan results:")
            print(wifi_results)
        elif choice == "8":
            print("Performing ARP network mapping scan...")
            arp_results = arp_scan_network()
            print("ARP scan results:")
            print(arp_results)
        elif choice == "9":
            print("Exiting the application. Goodbye!")
            exit(0)
        else:
            print("Invalid choice. Please try again.")


# ----------------------- Main Application Entry -----------------------
def main():
    user_choice = interactive_menu()
    if user_choice == "gui":
        # Start the Flask API server in a separate thread.
        api_thread = threading.Thread(target=start_api_server, daemon=True)
        api_thread.start()
        # Start cleanup thread.
        cleanup_thread = threading.Thread(target=cleanup_old_entries, daemon=True)
        cleanup_thread.start()
        # Launch the GUI (after a login dialog).
        app_gui = QApplication(sys.argv)
        app_gui.setStyle("Fusion")
        login = LoginDialog()
        if login.exec_() == QDialog.Accepted:
            main_window = MainWindow()
            main_window.show()
            sys.exit(app_gui.exec_())
        else:
            print("Login failed or canceled. Exiting.")
            sys.exit(0)


if __name__ == "__main__":
    main()
