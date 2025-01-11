import socket
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import csv
import asyncio
import pandas as pd
import os
from threading import Thread
import json

# Stop flag to control the scanning process
stop_flag = False
report_file = "port_scan_history.json"

def load_previous_reports():
    if os.path.exists(report_file):
        with open(report_file, "r") as file:
            return json.load(file)
    return {}

def save_reports(reports):
    with open(report_file, "w") as file:
        json.dump(reports, file, indent=4)

def compare_reports(ip, current_report, previous_report, output_box):
    output_box.insert(tk.END, "\nComparison with previous scan:\n", "blue")
    if not previous_report:
        output_box.insert(tk.END, "No previous report found for this IP.\n", "blue")
        return
    current_open_ports = set(current_report)
    previous_open_ports = set(previous_report)
    new_open_ports = current_open_ports - previous_open_ports
    closed_ports = previous_open_ports - current_open_ports

    if new_open_ports:
        output_box.insert(tk.END, f"Newly opened ports: {sorted(new_open_ports)}\n", "green")
    else:
        output_box.insert(tk.END, "No new ports opened since last scan.\n", "green")

    if closed_ports:
        output_box.insert(tk.END, f"Ports closed since last scan: {sorted(closed_ports)}\n", "red")
    else:
        output_box.insert(tk.END, "No ports closed since last scan.\n", "red")

async def check_port(ip, port, timeout, protocol):
    try:
        if protocol == "TCP":
            reader, writer = await asyncio.open_connection(ip, port)
            writer.close()
            await writer.wait_closed()
        elif protocol == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (ip, port))
            try:
                sock.recvfrom(1024)
            except socket.timeout:
                pass
            sock.close()
        return port
    except:
        return None

async def check_ports(ip, timeout, protocol, start_port, end_port, progress_bar, output_box):
    global stop_flag
    open_ports = []
    total_ports = end_port - start_port + 1

    async def progress_wrapper(port):
        global stop_flag
        if stop_flag:
            return None
        result = await check_port(ip, port, timeout, protocol)
        progress_bar['value'] += 100 / total_ports
        root.update_idletasks()
        if result:
            open_ports.append(result)
            output_box.insert(tk.END, f"Port {port} is open.\n", "green")
        else:
            output_box.insert(tk.END, f"Port {port} is closed.\n", "red")
        output_box.yview(tk.END)

    tasks = [progress_wrapper(port) for port in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)
    return open_ports

def run_check_ports(ip, timeout, protocol, start_port, end_port, progress_bar, output_box):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    open_ports = loop.run_until_complete(check_ports(ip, timeout, protocol, start_port, end_port, progress_bar, output_box))
    loop.close()
    return open_ports

def show_open_ports(ip, output_box, timeout, protocol, progress_bar, start_port, end_port):
    global stop_flag
    stop_flag = False
    output_box.insert(tk.END, "Starting to check ports...\n")
    output_box.yview(tk.END)

    previous_reports = load_previous_reports()
    previous_report = previous_reports.get(ip, [])

    thread = Thread(target=lambda: run_check_ports(ip, timeout, protocol, start_port, end_port, progress_bar, output_box))
    thread.start()
    thread.join()

    if not stop_flag:
        current_report = run_check_ports(ip, timeout, protocol, start_port, end_port, progress_bar, output_box)
        compare_reports(ip, current_report, previous_report, output_box)

        previous_reports[ip] = current_report
        save_reports(previous_reports)

        messagebox.showinfo("Process Complete", "Port check completed successfully!")
    else:
        output_box.insert(tk.END, "\nScan stopped by user.\n", "red")

def stop_scanning():
    global stop_flag
    stop_flag = True
    messagebox.showinfo("Stopped", "Scanning has been stopped.")

def save_report(output_box):
    content = output_box.get(1.0, tk.END).strip().split("\n")
    if not content:
        messagebox.showerror("Error", "No data to save.")
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".xlsx", 
                                             filetypes=[("Excel Files", "*.xlsx"), ("CSV Files", "*.csv")])
    if save_path:
        if save_path.endswith(".csv"):
            with open(save_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                for line in content:
                    writer.writerow([line])
        else:
            df = pd.DataFrame(content, columns=["Results"])
            df.to_excel(save_path, index=False)
        messagebox.showinfo("Saved", f"Report saved to {save_path}")

def on_check_button_click(event=None):
    ip = entry_ip.get()
    timeout = int(entry_timeout.get()) if entry_timeout.get() else 1
    protocol = protocol_var.get()
    start_port = int(entry_start_port.get()) if entry_start_port.get() else 1
    end_port = int(entry_end_port.get()) if entry_end_port.get() else 65535

    if not ip:
        messagebox.showerror("Error", "Please enter an IP or DNS address.")
        return

    check_button.config(state=tk.DISABLED)
    output_box.delete(1.0, tk.END)
    progress_bar['value'] = 0

    Thread(target=show_open_ports, args=(ip, output_box, timeout, protocol, progress_bar, start_port, end_port)).start()
    check_button.config(state=tk.NORMAL)

# GUI setup
root = tk.Tk()
root.title("Open Port Checker")
root.geometry("450x530")  # Reduced height by 70px
root.resizable(False, False)  # Prevent resizing

# Right frame for the main content
right_frame = tk.Frame(root)
right_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

label_ip = tk.Label(right_frame, text="IP or DNS Address:")
label_ip.grid(row=0, column=0)

entry_ip = tk.Entry(right_frame)
entry_ip.grid(row=0, column=1)

label_timeout = tk.Label(right_frame, text="Timeout (seconds):")
label_timeout.grid(row=1, column=0)

entry_timeout = tk.Entry(right_frame)
entry_timeout.grid(row=1, column=1)
entry_timeout.insert(tk.END, "1")

protocol_var = tk.StringVar(value="TCP")
tcp_radio = tk.Radiobutton(right_frame, text="TCP", variable=protocol_var, value="TCP")
tcp_radio.grid(row=2, column=0)
udp_radio = tk.Radiobutton(right_frame, text="UDP", variable=protocol_var, value="UDP")
udp_radio.grid(row=2, column=1)

label_start_port = tk.Label(right_frame, text="Start Port:")
label_start_port.grid(row=3, column=0)

entry_start_port = tk.Entry(right_frame)
entry_start_port.grid(row=3, column=1)
entry_start_port.insert(tk.END, "1")

label_end_port = tk.Label(right_frame, text="End Port:")
label_end_port.grid(row=4, column=0)

entry_end_port = tk.Entry(right_frame)
entry_end_port.grid(row=4, column=1)
entry_end_port.insert(tk.END, "65535")

buttons_frame = tk.Frame(right_frame)
buttons_frame.grid(row=5, column=0, columnspan=2)

check_button = tk.Button(buttons_frame, text="Check Ports", command=on_check_button_click)
check_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(buttons_frame, text="Stop", command=stop_scanning)
stop_button.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(buttons_frame, text="Save Report", command=lambda: save_report(output_box))
save_button.pack(side=tk.LEFT, padx=5)

output_box = tk.Text(right_frame, height=15, width=50)
output_box.grid(row=6, column=0, columnspan=2)
output_box.tag_configure("green", foreground="green")
output_box.tag_configure("red", foreground="red")
output_box.tag_configure("blue", foreground="blue")

progress_bar = ttk.Progressbar(right_frame, length=300)
progress_bar.grid(row=7, column=0, columnspan=2)

root.mainloop()
