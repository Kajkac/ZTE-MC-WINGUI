import tkinter as tk
from tkinter import scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import json
import time
import configparser
import os
import requests
import re
from requests.exceptions import SSLError
from mc import zteRouter

CONFIG_FILE = "config.ini"

def format_sms(sms_data, order_number):
    number = sms_data.get("number", "")
    message = sms_data.get("content", "")
    formatted_sms = f"{order_number}. Phone number: {number}\tMessage: {message}"
    return formatted_sms

def clear_inbox():
    # Destroy all widgets inside the inbox_frame_container
    for widget in inbox_frame_container.winfo_children():
        widget.destroy()
    # Reset the row counter to 0
    global inbox_row
    inbox_row = 0

def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    else:
        config['DEFAULT'] = {'RouterIP': '', 'RouterPassword': ''}
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    return config['DEFAULT']

def save_config(ip, password):
    config = configparser.ConfigParser()
    config['DEFAULT'] = {'RouterIP': ip, 'RouterPassword': password}
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def fetch_router_model(ip):
    try:
        # Try HTTPS first
        url = f"https://{ip}/js/config/config.js"
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            match = re.search(r'DEVICE_MODEL:"([^"]+)"', response.text)
            if match:
                model_name = match.group(1)
                # Fetching wa_inner_version
                wa_inner_version_url = f"https://{ip}/goform/goform_get_cmd_process?isTest=false&cmd=Language%2Ccr_version%2Cwa_inner_version%2Cmodem_main_state&multi_data=1&_=1716895312378"
                wa_inner_version_response = requests.get(wa_inner_version_url, verify=False)
                if wa_inner_version_response.status_code == 200:
                    wa_inner_version_data = wa_inner_version_response.json()
                    wa_inner_version = wa_inner_version_data.get('wa_inner_version', 'Unknown')
                    return f"{model_name} ( Version: {wa_inner_version})"
        # If HTTPS fails, try HTTP
    except SSLError:
        try:
            url = f"http://{ip}/js/config/config.js"
            response = requests.get(url)
            if response.status_code == 200:
                match = re.search(r'DEVICE_MODEL:"([^"]+)"', response.text)
                if match:
                    model_name = match.group(1)
                    # Fetching wa_inner_version
                    wa_inner_version_url = f"http://{ip}/goform/goform_get_cmd_process?isTest=false&cmd=Language%2Ccr_version%2Cwa_inner_version%2Cmodem_main_state&multi_data=1&_=1716895312378"
                    wa_inner_version_response = requests.get(wa_inner_version_url)
                    if wa_inner_version_response.status_code == 200:
                        wa_inner_version_data = wa_inner_version_response.json()
                        wa_inner_version = wa_inner_version_data.get('wa_inner_version', 'Unknown')
                        return f"{model_name} ( Version: {wa_inner_version})"
        except Exception as e:
            print(f"Error fetching router model: {e}")
    except Exception as e:
        print(f"Error fetching router model: {e}")
    return "Unknown Model"

def update_router_model_label(ip):
    model_name = fetch_router_model(ip)
    router_model_label.config(text=f"Router Model: {model_name}")

def execute_command(ip_entry, password_entry, ha_select, phone_number_entry=None, message_entry=None):
    ip = ip_entry.get()
    password = password_entry.get()
    
    if not ip or not password:
        if ha_select == 2:
            sms_console.insert(tk.END, "No IP or password supplied\n")
        else:
            console.insert(tk.END, "No IP or password supplied\n")
        return
    
    clear_consoles()
    
    # Instantiate zteRouter with IP address and password
    zte_instance = zteRouter(ip, password)
    
    if ha_select == 1:
        clear_inbox()
        try:
            result = zte_instance.parsesms()
            sms_data = json.loads(result)
            for i, message in enumerate(sms_data["messages"], 1):  # Start counting from 1
                formatted_sms = format_sms(message, i)
                add_sms_to_inbox(formatted_sms)  # Add formatted SMS to the inbox
        except Exception as e:
            add_sms_to_inbox(f"Error: {str(e)}\n")
    elif ha_select == 2:
        phone_number = phone_number_entry.get()
        message = message_entry.get()
        if not phone_number or not message:
            sms_console.insert(tk.END, "Phone number or message not supplied\n")
            return
        zte_instance.sendsms(phone_number, message)
        sms_console.insert(tk.END, "SMS sent.\n")
    elif ha_select == 3:
        time.sleep(3)
        result = zte_instance.zteinfo()
        console.insert(tk.END, f"{result}\n")
        display_info(result)
        update_signal_bar(json.loads(result).get('signalbar', ''))
    elif ha_select == 4:
        zte_instance.ztereboot()
        console.insert(tk.END, "Rebooted.\n")
    elif ha_select == 5:
        result = zte_instance.parsesms()
        data = json.loads(result)
        ids = [message['id'] for message in data['messages']]
        formatted_ids = ";".join(ids)
        console.insert(tk.END, f"Formatted IDs: {formatted_ids}\n")
        zte_instance.deletesms(formatted_ids)
        console.insert(tk.END, "Deleted SMS.\n")
    elif ha_select == 6:
        time.sleep(6)
        json_string = zte_instance.ztesmsinfo()
        totalztememory = 100
        dictionary = json.loads(json_string)
        nv_rev_total = int(dictionary['sms_nv_rev_total'])
        nv_send_total = int(dictionary['sms_nv_send_total'])
        total = nv_rev_total + nv_send_total
        totalremaining = totalztememory - total
        console.insert(tk.END, f"You have {totalremaining} messages left of 100\n")
    elif ha_select == 7:
        time.sleep(3)
        result = zte_instance.zteinfo2()
        console.insert(tk.END, f"{result}\n")
        display_info(result)
        update_signal_bar(json.loads(result).get('signalbar', ''))
    else:
        console.insert(tk.END, "ELSE\n")

def display_info(result):
    data = json.loads(result)
    info_labels = [
        ("WA Inner Version:", data.get("wa_inner_version", "")),
        ("CR Version:", data.get("cr_version", "")),
        ("Network Type:", data.get("network_type", "")),
        ("RSSI:", data.get("rssi", "")),
        ("RSCP:", data.get("rscp", "")),
        ("RMCC:", data.get("rmcc", "")),
        ("RMNC:", data.get("rmnc", "")),
        ("ENodeB ID:", data.get("enodeb_id", "")),
        ("LTE RSRQ:", data.get("lte_rsrq", "")),
        ("LTE RSRP:", data.get("lte_rsrp", "")),
        ("5G SNR:", data.get("Z5g_snr", "")),
        ("5G RSRP:", data.get("Z5g_rsrp", "")),
        ("ZCELLINFO Band:", data.get("ZCELLINFO_band", "")),
        ("5G DL Earfcn:", data.get("Z5g_dlEarfcn", "")),
        ("LTE CA PCell Arfcn:", data.get("lte_ca_pcell_arfcn", "")),
        ("LTE CA PCell Band:", data.get("lte_ca_pcell_band", "")),
        ("LTE CA SCell Band:", data.get("lte_ca_scell_band", "")),
        ("LTE CA PCell Bandwidth:", data.get("lte_ca_pcell_bandwidth", "")),
        ("LTE CA SCell Info:", data.get("lte_ca_scell_info", "")),
        ("LTE CA SCell Bandwidth:", data.get("lte_ca_scell_bandwidth", "")),
        ("WAN LTE CA:", data.get("wan_lte_ca", "")),
        ("LTE PCI:", data.get("lte_pci", "")),
        ("5G Cell ID:", data.get("Z5g_CELL_ID", "")),
        ("5G SINR:", data.get("Z5g_SINR", "")),
        ("Cell ID:", data.get("cell_id", "")),
        ("WAN Active Band:", data.get("wan_active_band", "")),
        ("WAN Active Channel:", data.get("wan_active_channel", "")),
        ("NR5G PCI:", data.get("nr5g_pci", "")),
        ("NR5G Action Band:", data.get("nr5g_action_band", "")),
        ("NR5G Cell ID:", data.get("nr5g_cell_id", "")),
        ("LTE SNR:", data.get("lte_snr", "")),
        ("ECIO:", data.get("ecio", "")),
        ("NR5G Action Channel:", data.get("nr5g_action_channel", "")),
        ("NGBR Cell Info:", data.get("ngbr_cell_info", "")),
        ("Monthly TX Bytes:", data.get("monthly_tx_bytes", "")),
        ("Monthly RX Bytes:", data.get("monthly_rx_bytes", "")),
        ("LTE PCI Lock:", data.get("lte_pci_lock", "")),
        ("LTE EARFCN Lock:", data.get("lte_earfcn_lock", "")),
        ("WAN IP Address:", data.get("wan_ipaddr", "")),
        ("WAN APN:", data.get("wan_apn", "")),
        ("PM Sensor MDM:", data.get("pm_sensor_mdm", "")),
        ("PM Modem 5G:", data.get("pm_modem_5g", "")),
        ("DNS Mode:", data.get("dns_mode", "")),
        ("Prefer DNS Manual:", data.get("prefer_dns_manual", "")),
        ("Standby DNS Manual:", data.get("standby_dns_manual", "")),
        ("Static WAN IP Address:", data.get("static_wan_ipaddr", "")),
        ("OPMS WAN Mode:", data.get("opms_wan_mode", "")),
        ("OPMS WAN Auto Mode:", data.get("opms_wan_auto_mode", "")),
        ("PPP Status:", data.get("ppp_status", "")),
        ("Loginfo:", data.get("loginfo", "")),
        ("Realtime Time:", data.get("realtime_time", "")),
        ("Signal Bar:", data.get("signalbar", "")),
    ]

    for i, (label_text, value) in enumerate(info_labels):
        if i < len(labels):
            labels[i].config(text=f"{label_text} {value}")
        else:
            new_label = ttk.Label(info_frame_container, text=f"{label_text} {value}", anchor="w")
            new_label.grid(row=i, column=0, sticky="w", padx=10, pady=5)
            labels.append(new_label)

def update_signal_bar(signal_value):
    colors = ["#ff0000", "#ff6600", "#ffcc00", "#99ff00", "#00ff00"]
    signal_value = int(signal_value) if signal_value.isdigit() else 0
    signal_value = max(0, min(signal_value, 5))
    for i in range(5):
        color = colors[i] if i < signal_value else "#dddddd"
        signal_canvas.itemconfig(signal_bars[i], fill=color, outline="black")



def clear_consoles():
    console.delete(1.0, tk.END)
    formatted_console.delete(1.0, tk.END)
    sms_console.delete(1.0, tk.END)

def on_closing():
    save_config(ip_entry.get(), password_entry.get())
    root.destroy()

def add_sms_to_inbox(message):
    global inbox_row
    inbox_label = ttk.Label(inbox_frame_container, text=message, wraplength=600, anchor="w")
    inbox_label.grid(row=inbox_row, column=0, sticky="ew", padx=5, pady=2)
    inbox_row += 1

# Load configuration
config = load_config()

# Set up the GUI
root = ttk.Window(themename="cosmo")  # Using ttkbootstrap window and theme
root.title("ZTE Administration Utility")
root.geometry("900x800")  # Expanded window size

# Router Model Label (on top)
router_model_label = ttk.Label(root, text="Router Model: Unknown", font=('TkDefaultFont', 12, 'bold'))
router_model_label.grid(row=0, column=0, columnspan=2, padx=(10, 5), pady=(10, 5))

# IP Address Label and Entry (above tabs)
ip_label = ttk.Label(root, text="Router IP:")
ip_label.grid(row=1, column=0, sticky="e", padx=(10, 5), pady=(10, 5))

ip_entry = ttk.Entry(root)
ip_entry.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=(10, 5))
ip_entry.insert(0, config['RouterIP'])  # Load saved IP address

# Password Label and Entry (above tabs)
password_label = ttk.Label(root, text="Router Password:")
password_label.grid(row=2, column=0, sticky="e", padx=(10, 5), pady=5)

password_entry = ttk.Entry(root, show="*")
password_entry.grid(row=2, column=1, sticky="w", padx=(0, 10), pady=5)
password_entry.insert(0, config['RouterPassword'])  # Load saved password

# Connect Button
connect_button = ttk.Button(root, text="Connect", command=lambda: execute_command(ip_entry, password_entry, 3))
connect_button.grid(row=2, column=2, padx=(0, 0), pady=0)

# Signal Bar Canvas with Signal Text
signal_label = ttk.Label(root, text="Signal:", font=('TkDefaultFont', 10))
signal_label.place(x=770, y=10)

signal_canvas = tk.Canvas(root, width=90, height=20)
signal_canvas.place(x=820, y=5)

signal_bars = []
for i in range(5):
    bar = signal_canvas.create_polygon(
        [i * 15, 20, (i + 1) * 15 - 3, 20, (i + 1) * 15 - 3, 20 - (i + 1) * 4, i * 15, 20 - (i + 1) * 4],
        fill="#dddddd", outline="black"
    )
    signal_bars.append(bar)


# Create the Notebook (tab container)
notebook = ttk.Notebook(root)
notebook.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Main tab
main_frame = ttk.Frame(notebook)
notebook.add(main_frame, text="Main")

# SMS tab
sms_frame = ttk.Frame(notebook)
notebook.add(sms_frame, text="Send SMS")

# SMS Inbox tab
inbox_frame = ttk.Frame(notebook)
notebook.add(inbox_frame, text="SMS Inbox")

# Create buttons for each command (on main tab)
commands = [
    ("Parse SMS", 1),
    ("Get ZTE Info", 3),
    ("Reboot ZTE", 4),
    ("Delete SMS", 5),
    ("Get SMS Info", 6),
    ("Get ZTE Info 2", 7),
]

for i, (text, value) in enumerate(commands):
    button = ttk.Button(main_frame, text=text, command=lambda v=value: execute_command(ip_entry, password_entry, v))
    button.grid(row=i, column=0, columnspan=2, sticky="ew", padx=10, pady=5)
    main_frame.grid_columnconfigure(0, weight=1, uniform="buttons")

# Create a console area to display output (on main tab)
console = scrolledtext.ScrolledText(main_frame, width=60, height=10, font=("TkDefaultFont", 10))
console.grid(row=len(commands), column=0, columnspan=2, padx=10, pady=10)

# Create another console for formatted SMS details (on main tab)
formatted_console = scrolledtext.ScrolledText(main_frame, width=60, height=5, font=("TkDefaultFont", 10))
formatted_console.grid(row=len(commands)+1, column=0, columnspan=2, padx=10, pady=10)

# Create a scrollable frame to display parsed information
info_frame = ttk.Frame(root)
info_frame.grid(row=3, column=3, rowspan=7, padx=10, pady=10, sticky="nsew")

info_canvas = tk.Canvas(info_frame)
info_scrollbar = ttk.Scrollbar(info_frame, orient="vertical", command=info_canvas.yview)
info_canvas.configure(yscrollcommand=info_scrollbar.set)

info_frame_container = ttk.Frame(info_canvas)

info_scrollbar.pack(side="right", fill="y")
info_canvas.pack(side="left", fill="both", expand=True)
info_canvas.create_window((0, 0), window=info_frame_container, anchor="nw")

info_frame_container.bind("<Configure>", lambda e: info_canvas.configure(scrollregion=info_canvas.bbox("all")))

labels = []

# Create a console area to display SMS sending output (on SMS tab)
sms_console = scrolledtext.ScrolledText(sms_frame, width=60, height=10, font=("TkDefaultFont", 10))
sms_console.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Phone Number Label and Entry (on SMS tab)
phone_number_label = ttk.Label(sms_frame, text="Phone Number:")
phone_number_label.grid(row=0, column=0, sticky="e", padx=(10, 5), pady=(10, 5))

phone_number_entry = ttk.Entry(sms_frame)
phone_number_entry.grid(row=0, column=1, sticky="w", padx=(0, 10), pady=(10, 5))

# Message Label and Entry (on SMS tab)
message_label = ttk.Label(sms_frame, text="Message:")
message_label.grid(row=1, column=0, sticky="e", padx=(10, 5), pady=5)

message_entry = ttk.Entry(sms_frame)
message_entry.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=5)

# Send SMS Button (on SMS tab)
send_sms_button = ttk.Button(sms_frame, text="Send SMS", command=lambda: execute_command(ip_entry, password_entry, 2, phone_number_entry, message_entry))
send_sms_button.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=5)

# Modify the Parse SMS button command to pass the appropriate ha_select value
parse_sms_button = ttk.Button(inbox_frame, text="Parse SMS", command=lambda: execute_command(ip_entry, password_entry, 1))
parse_sms_button.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=5)

# Create a canvas to contain the SMS messages (on SMS Inbox tab)
inbox_canvas = tk.Canvas(inbox_frame)
inbox_canvas.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

# Create a frame to hold the SMS messages inside the canvas
inbox_frame_container = ttk.Frame(inbox_canvas)
inbox_frame_container.grid(row=0, column=0, sticky="nsew")

# Add a scrollbar for the canvas
scrollbar = ttk.Scrollbar(inbox_frame, orient="vertical", command=inbox_canvas.yview)
scrollbar.grid(row=0, column=1, sticky="ns")
inbox_canvas.configure(yscrollcommand=scrollbar.set)

# Configure the canvas to expand with the window
inbox_frame.grid_rowconfigure(0, weight=1)
inbox_frame.grid_columnconfigure(0, weight=1)

# Bind the canvas to the scrollbar
inbox_canvas.create_window((0, 0), window=inbox_frame_container, anchor="nw")

# Function to update the scroll region when the frame size changes
def inbox_configure_scroll_region(event):
    inbox_canvas.configure(scrollregion=inbox_canvas.bbox("all"))

inbox_frame_container.bind("<Configure>", inbox_configure_scroll_region)

inbox_row = 0  # Track the current row in the inbox grid

# Update router model label based on the loaded IP address
update_router_model_label(ip_entry.get())

# Bind the on_closing function to the window close event
root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
