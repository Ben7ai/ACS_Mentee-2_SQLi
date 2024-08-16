import requests
from urllib.parse import urlparse, parse_qs
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import os
import logging
import threading

# Configuration for payloads path and logging
PAYLOADS_PATH = ['SQL-Time.txt']
LOG = 1
DISPLAY_PACKETS = True  # Toggle for displaying packets

# Setup logging to a file
logging.basicConfig(filename='sql_injection_tool.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class SQLInjectionTool:
    def __init__(self, master):
        self.master = master
        self.master.title("SQL Injection Testing Tool")

        # Create and place widgets
        self.url_label = tk.Label(master, text="Enter the URL:")
        self.url_label.pack(pady=5)

        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.pack(pady=5)

        self.param_label = tk.Label(master, text="POST Parameters (username, password, session_token):")
        self.param_label.pack(pady=5)

        self.param_entry = tk.Entry(master, width=50)
        self.param_entry.insert(0, "username=user&password=pass&session_token=token")
        self.param_entry.pack(pady=5)

        self.packet_toggle = tk.Checkbutton(master, text="Display Packets", variable=tk.IntVar(value=DISPLAY_PACKETS), command=self.toggle_packets)
        self.packet_toggle.pack(pady=5)

        self.test_button = tk.Button(master, text="Start Testing", command=self.start_testing_thread)
        self.test_button.pack(pady=5)

        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10, padx=10, side="bottom")

        self.time_label = tk.Label(master, text="Estimated Time: N/A")
        self.time_label.pack(pady=5)

        self.status_label = tk.Label(master, text="")
        self.status_label.pack(pady=5)

        self.log_text = tk.Text(master, height=10, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(pady=5)

    def toggle_packets(self):
        global DISPLAY_PACKETS
        DISPLAY_PACKETS = not DISPLAY_PACKETS

    def get_processor(self, url):
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        path = parsed_url.path
        return netloc, path

    def get_request_send(self, url, data):
        """
        Sends a POST request to the constructed URL with provided POST parameters (data).
        """
        try:
            r = requests.post(url=url, data=data, timeout=10)
            r.raise_for_status()
            if DISPLAY_PACKETS:
                self.log_message(f"Sent POST Request:\nURL: {url}\nData: {data}\nResponse Code: {r.status_code}")
        except requests.exceptions.RequestException as e:
            self.log_message(f"Error making request: {e}")
            return None, url
        return r, url

    def check_compatibility(self, url, data):
        """
        Checks if the website is compatible with this tool by testing basic queries via POST method.
        """
        test_payload = "1"
        data_with_payload = {key: value + test_payload for key, value in data.items()}
        r, url_test = self.get_request_send(url, data_with_payload)
        if r and r.status_code == 200:
            return True
        return False

    def process_payload_sleep_post(self, url, data):
        """
        Processes the payloads from the file and tests for SQL injection vulnerabilities.
        """
        total_payloads = 0
        for payloads_path in PAYLOADS_PATH:
            if not os.path.isfile(payloads_path):
                self.log_message(f"Error: The file does not exist: {payloads_path}")
                self.status_label.config(text=f"Error: The file does not exist: {payloads_path}")
                return

            try:
                with open(payloads_path, 'r') as f:
                    payloads = f.readlines()
                total_payloads += len(payloads)
            except Exception as e:
                self.log_message(f"Error opening file: {payloads_path} - {e}")
                self.status_label.config(text=f"Error opening file: {payloads_path}")
                return

        if total_payloads == 0:
            self.status_label.config(text="No payloads to process.")
            return

        self.progress["maximum"] = total_payloads
        processed_payloads = 0
        start_time = time.time()

        for payloads_path in PAYLOADS_PATH:
            try:
                with open(payloads_path, 'r') as f:
                    payloads = f.readlines()
            except Exception as e:
                self.log_message(f"Error opening file: {payloads_path} - {e}")
                self.status_label.config(text=f"Error opening file: {payloads_path}")
                return

            for payload in payloads:
                payload = payload.strip()
                for key in data:
                    data_with_payload = data.copy()
                    data_with_payload[key] = data[key] + payload

                    start_time_payload = time.time()
                    r, url_test = self.get_request_send(url, data_with_payload)
                    if r is None:
                        continue

                    elapsed_time = time.time() - start_time_payload

                    if LOG == 1:
                        current_time = datetime.now().time().strftime("%H:%M:%S")
                        self.log_message(f'[{current_time}] Payload testing: {payload}')

                    if elapsed_time >= 5:
                        recheck_payload = payload.replace("5", "10")
                        data_with_payload[key] = data[key] + recheck_payload

                        if LOG == 1:
                            self.log_message(f"[!] Recheck payload: {recheck_payload}")

                        recheck_start_time = time.time()
                        r, url_test = self.get_request_send(url, data_with_payload)
                        if r is None:
                            continue

                        recheck_elapsed_time = time.time() - recheck_start_time
                        if recheck_elapsed_time >= 10:
                            self.log_message('[+] SQL injection vulnerabilities detected')
                            self.log_message(f'[+] URL: {url_test}')
                            self.log_message(f'[+] Payload: {payload}')
                            self.status_label.config(text="SQL injection vulnerabilities detected")
                            return

                    processed_payloads += 1
                    self.progress["value"] = processed_payloads
                    self.master.update_idletasks()

                    # Estimate remaining time
                    elapsed_total_time = time.time() - start_time
                    average_time_per_payload = elapsed_total_time / processed_payloads
                    remaining_payloads = total_payloads - processed_payloads
                    estimated_time_remaining = max(average_time_per_payload * remaining_payloads, 0)  # Ensure non-negative value
                    self.time_label.config(text=f"Estimated Time: {self.format_time(estimated_time_remaining)}")

                    self.master.update_idletasks()

    def format_time(self, seconds):
        minutes, seconds = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.yview(tk.END)
        self.log_text.config(state=tk.DISABLED)
        logging.info(message)

    def start_testing(self):
        url = self.url_entry.get()
        if not url:
            self.status_label.config(text="URL cannot be empty.")
            return

        post_params = self.param_entry.get()
        data = dict(parse_qs(post_params))
        data = {key: value[0] for key, value in data.items()}

        self.status_label.config(text="Starting testing...")
        self.log_message("Starting testing...")
        
        if self.check_compatibility(url, data):
            self.status_label.config(text="Website is compatible. Proceeding with the test.")
            self.process_payload_sleep_post(url, data)
            self.status_label.config(text="Testing complete.")
        else:
            self.status_label.config(text="Website is not compatible. Exiting.")
            self.log_message("Website is not compatible. Exiting.")

    def start_testing_thread(self):
        testing_thread = threading.Thread(target=self.start_testing)
        testing_thread.start()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SQLInjectionTool(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
