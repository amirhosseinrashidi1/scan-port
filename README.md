Open Port Checker

Overview

Open Port Checker is a Python-based GUI tool for scanning open ports on a specified IP or DNS address. The application utilizes `Tkinter` for its graphical interface and supports both TCP and UDP protocols. 

Features

Port Scanning: Check a range of ports on a target IP/DNS for open or closed status.
Comparison: Compares current scan results with previous scans to identify new or closed ports.
Save Reports: Export scan results to CSV or Excel files for further analysis.
Stop Scanning: Ability to interrupt a scan process at any time.
Protocol Support: Scans can be performed over TCP or UDP protocols.

How It Works

1. Input the IP or DNS address, port range, timeout, and protocol (TCP/UDP).
2. The application scans the specified range of ports and displays their status in real-time.
3. Scan results are stored in a JSON file (`port_scan_history.json`) for future comparisons.
4. Reports can be saved in either CSV or Excel format.
5. The GUI provides a progress bar to indicate scan completion.

Requirements

Python 3.8 or later
Required Python libraries: `socket`, `tkinter`, `asyncio`, `pandas`, `csv`, `json`, and `threading`.
