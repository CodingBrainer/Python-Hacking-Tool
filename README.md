# Python Hacking Tool

Advanced Cybersecurity Suite
============================

Overview:
---------
This project is a proof-of-concept cybersecurity tool that integrates a wide range of
features to demonstrate how AI and automation can help keep networks safe. It includes:

  • Passive network monitoring (SYN scan detection, basic DPI)
  • Active scanning using Nmap
  • Machine Learning anomaly detection (Isolation Forest and a stub for deep learning)
  • Threat Intelligence lookups via external APIs (stubbed for AbuseIPDB and multi-feed integration)
  • Automated incident response (e.g., blocking IPs via iptables, dynamic firewall adjustments)
  • Forensic capabilities (saving PCAP files for suspicious activity)
  • Distributed sensor integration stub (e.g., sending alerts to a message broker)
  • RESTful API endpoints (via Flask) for external integration and ChatOps queries
  • An interactive CLI menu and a feature-rich GUI (with login, real-time logs, tables, and graphs)
  
Additional Advanced Features:
  • SSH Brute Force Module (using Paramiko) – for penetration testing (use only on authorized systems)
  • WiFi Scanning – lists available WiFi networks using the “nmcli” command (Linux)
  • ARP Network Mapping – performs an ARP scan to map the local network (requires arp-scan)
  
Usage:
------
1. Install dependencies:
   pip install -r requirements.txt

2. Ensure that Nmap is installed and available in your PATH.
   For WiFi scanning and ARP network mapping on Linux, ensure that “nmcli” and “arp-scan”
   are installed and that you have the necessary privileges.

3. Run the tool:
   python advanced_cyber_suite.py

4. Upon startup, an interactive CLI menu is presented with the following options:
   1. Start passive monitoring (GUI mode)
   2. Run a manual Nmap scan
   3. Perform a Threat Intelligence lookup on an IP
   4. Execute automated incident response (block an IP)
   5. ChatOps query
   6. SSH brute force attack (penetration testing)
   7. Scan available WiFi networks
   8. ARP network mapping scan
   9. Exit

5. Choosing option 1 launches the full GUI mode.
   - The GUI requires a login. Default credentials are:
       Username: admin
       Password: password
   - In GUI mode, you can view real-time logs, a table of suspicious IPs,
     and a dynamic graph of SYN counts. You can also manually trigger Nmap scans.

Notes:
------
- This tool is intended for educational purposes and as a demonstration.
- **Do not use brute force, WiFi scanning, or network mapping features on networks
  where you do not have explicit authorization.**
- Some functions (e.g., iptables blocking, nmcli, arp-scan) require root privileges.
- Many features (e.g., deep learning anomaly detection, multi-feed threat intelligence,
  distributed sensor integration, ChatOps integration) are provided as stubs for future
  expansion.

License:
--------
This project is provided for educational purposes and as a portfolio demonstration.
Use and modify it at your own risk.

Happy coding and stay safe! - FROM CODINGBRAINER 
