import requests
from urllib.parse import urlparse, parse_qs
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import os
import logging

# Configuration for payloads path and logging
PAYLOADS_PATH = ['SQL-Time.txt']
LOG = 1

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

        self.test_button = tk.Button(master, text="Start Testing", command=self.start_testing)
        self.test_button.pack(pady=5)

        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10, padx=10, side="bottom")

        self.time_label = tk.Label(master, text="Estimated Time: N/A")
        self.time_label.pack(pady=5)

        self.status_label = tk.Label(master, text="")
        self.status_label.pack(pady=5)

        self.log_text = tk.Text(master, height=10, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(pady=5)

    def get_processor(self, url):
        parsed_url = urlparse(url)
        query_parameters_ = parse_qs(parsed_url.query)
        query_parameters = {key: value[0] for key, value in query_parameters_.items()}
        netloc = parsed_url.netloc
        path = parsed_url.path
        return netloc, path, query_parameters

    def get_request_send(self, netloc, path, query_parameters):
        url = f'https://{netloc}{path}?'
        url += '&'.join(f'{key}={value}' for key, value in query_parameters.items())
        try:
            r = requests.get(url=url, timeout=10)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            self.log_message(f"Error making request: {e}")
            return None, url
        return r, url

    def check_compatibility(self, netloc, path, query_parameters):
        test_payload = "1"
        for key in query_parameters:
            query_parameters_payload = query_parameters.copy()
            query_parameters_payload[key] = query_parameters[key] + test_payload
            r, url_test = self.get_request_send(netloc, path, query_parameters_payload)
            if r and r.status_code == 200:
                return True
        return False

    def process_payload_sleep_get(self, netloc, path, query_parameters):
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
                for key, value in query_parameters.items():
                    query_parameters_payload = query_parameters.copy()
                    query_parameters_payload[key] = value + payload
                    
                    start_time_payload = time.time()
                    r, url_test = self.get_request_send(netloc, path, query_parameters_payload)
                    if r is None:
                        continue
                    
                    elapsed_time = time.time() - start_time_payload
                    
                    if LOG == 1:
                        current_time = datetime.now().time().strftime("%H:%M:%S")
                        self.log_message(f'[{current_time}] Payload testing: {payload}')
                    
                    if elapsed_time >= 5:
                        recheck_payload = payload.replace("5", "10")
                        query_parameters_payload[key] = value + recheck_payload
                        
                        if LOG == 1:
                            self.log_message(f"[!] Recheck payload: {recheck_payload}")
                        
                        recheck_start_time = time.time()
                        r, url_test = self.get_request_send(netloc, path, query_parameters_payload)
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
                    estimated_time_remaining = average_time_per_payload * remaining_payloads
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

        self.status_label.config(text="Starting testing...")
        self.log_message("Starting testing...")
        netloc, path, query_parameters = self.get_processor(url)
        
        if self.check_compatibility(netloc, path, query_parameters):
            self.status_label.config(text="Website is compatible. Proceeding with the test.")
            self.process_payload_sleep_get(netloc, path, query_parameters)
            self.status_label.config(text="Testing complete.")
        else:
            self.status_label.config(text="Website is not compatible. Exiting.")
            self.log_message("Website is not compatible. Exiting.")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SQLInjectionTool(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"An error occurred: {e}")
