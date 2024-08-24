import requests
from urllib.parse import urlparse, parse_qs, urljoin
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog
import os
import logging
import threading

# Configuration for payloads path and logging
LOG = 1
DISPLAY_PACKETS = True  # Toggle for displaying packets
MAX_RETRIES = 3  # Maximum number of retries in case of timeout

# Setup logging to a file
logging.basicConfig(filename='sql_injection_tool.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class SQLInjectionTool:
    def __init__(self, master):
        self.master = master
        self.master.title("SQL Injection Testing Tool")

        self.payloads_path = None  # Initialize payloads_path as None
        self.post_data = None
        self.endpoint = None
        self.cookies = None

        # Create and place widgets
        self.upload_button = tk.Button(master, text="Upload Request File", command=self.upload_request_file)
        self.upload_button.pack(pady=5)

        self.url_label = tk.Label(master, text="Enter the URL:")
        self.url_label.pack(pady=5)

        self.url_entry = tk.Entry(master, width=50)
        self.url_entry.pack(pady=5)

        self.endpoint_label = tk.Label(master, text="Endpoint (e.g., /login):")
        self.endpoint_label.pack(pady=5)

        self.endpoint_entry = tk.Entry(master, width=50)
        self.endpoint_entry.pack(pady=5)

        self.param_label = tk.Label(master, text="POST Parameters (username=user&password=pass):")
        self.param_label.pack(pady=5)

        self.param_entry = tk.Entry(master, width=50)
        self.param_entry.pack(pady=5)

        self.cookie_label = tk.Label(master, text="Cookies (optional):")
        self.cookie_label.pack(pady=5)

        self.cookie_entry = tk.Entry(master, width=50)
        self.cookie_entry.pack(pady=5)

        self.packet_toggle = tk.Checkbutton(master, text="Disable Display Packets", variable=tk.IntVar(value=DISPLAY_PACKETS), command=self.toggle_packets)
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

    def upload_request_file(self):
        file_path = filedialog.askopenfilename(title="Select POST Request File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if file_path:
            self.parse_request_file(file_path)
        else:
            self.status_label.config(text="No request file selected.")

    def parse_request_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()

            if not lines:
                self.status_label.config(text="File is empty.")
                return

            # Extract URL and endpoint from the request
            first_line = lines[0].strip()
            method, path, _ = first_line.split()
            if method == "POST":
                self.endpoint = path
                url = urlparse(file_path).scheme + "://" + urlparse(file_path).netloc
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, url)

            # Extract POST data
            for i, line in enumerate(lines):
                if line.startswith("Content-Length:"):
                    content_length = int(line.split(":")[1].strip())
                    post_data_start = i + 1
                    post_data_end = post_data_start + content_length
                    self.post_data = "".join(lines[post_data_start:post_data_end]).strip()
                    self.param_entry.delete(0, tk.END)
                    self.param_entry.insert(0, self.post_data)
                    break

            # Extract cookies
            for line in lines:
                if line.startswith("Cookie:"):
                    cookie_str = line.split(":", 1)[1].strip()
                    self.cookies = dict(parse_qs(cookie_str))
                    self.cookie_entry.delete(0, tk.END)
                    self.cookie_entry.insert(0, cookie_str)
                    break

            self.status_label.config(text="Request file processed successfully.")
        except Exception as e:
            self.log_message(f"Error processing request file: {e}")
            self.status_label.config(text=f"Error processing request file: {e}")

    def get_request_send(self, url, endpoint, data, cookies):
        """
        Sends a POST request to the constructed URL with provided POST parameters (data),
        including cookies if provided, and implementing retry on timeout and error logging.
        """
        retries = 0
        while retries < MAX_RETRIES:
            try:
                full_url = urljoin(url, endpoint)
                r = requests.post(full_url, data=data, cookies=cookies, timeout=10, allow_redirects=False)
                r.raise_for_status()
                if DISPLAY_PACKETS:
                    self.log_message(f"Sent POST Request:\nURL: {full_url}\nData: {data}\nCookies: {cookies}\nResponse Code: {r.status_code}")
                return r, full_url  # Successful request, return the response

            except requests.exceptions.Timeout as e:
                retries += 1
                self.log_message(f"Timeout occurred: {e}. Retrying ({retries}/{MAX_RETRIES})...")
                if retries >= MAX_RETRIES:
                    self.log_message(f"Failed after {MAX_RETRIES} retries due to timeout.")
                    return None, full_url  # Return None if max retries reached

            except requests.exceptions.RequestException as e:
                self.log_message(f"Error making request: {e}")
                return None, full_url  # For other request-related errors

        return None, full_url  # In case of failure after retries

    def check_compatibility(self, url, endpoint, data, cookies):
        """
        Checks if the website is compatible with this tool by testing basic queries via POST method.
        """
        test_payload = "1"
        data_with_payload = {key: value + test_payload for key, value in data.items()}
        r, url_test = self.get_request_send(url, endpoint, data_with_payload, cookies)
        if r and r.status_code == 200:
            return True
        return False

    def process_payload_sleep_post(self, url, endpoint, data, cookies):
        """
        Processes the payloads from the file and tests for SQL injection vulnerabilities.
        """
        if not self.payloads_path or not os.path.isfile(self.payloads_path):
            self.log_message(f"Error: No payloads file selected or the file does not exist.")
            self.status_label.config(text=f"Error: No payloads file selected or the file does not exist.")
            return

        try:
            with open(self.payloads_path, 'r') as f:
                payloads = f.readlines()
        except Exception as e:
            self.log_message(f"Error opening file: {self.payloads_path} - {e}")
            self.status_label.config(text=f"Error opening file: {self.payloads_path}")
            return

        total_payloads = len(payloads)
        if total_payloads == 0:
            self.status_label.config(text="No payloads to process.")
            return

        self.progress["maximum"] = total_payloads
        processed_payloads = 0
        start_time = time.time()

        for payload in payloads:
            payload = payload.strip()
            for key in data:
                data_with_payload = data.copy()
                data_with_payload[key] = data[key] + payload

                start_time_payload = time.time()
                r, url_test = self.get_request_send(url, endpoint, data_with_payload, cookies)
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
                    r, url_test = self.get_request_send(url, endpoint, data_with_payload, cookies)
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
        endpoint = self.endpoint_entry.get()
        if not url or not endpoint:
            self.status_label.config(text="URL and endpoint cannot be empty.")
            return

        post_params = self.param_entry.get()
        data = dict(parse_qs(post_params))
        data = {key: value[0] for key, value in data.items()}

        cookies = {}
        cookie_string = self.cookie_entry.get()
        if cookie_string:
            cookies = dict(parse_qs(cookie_string))
            cookies = {key: value[0] for key, value in cookies.items()}

        self.status_label.config(text="Starting testing...")
        self.log_message("Starting testing...")
        
        if self.check_compatibility(url, endpoint, data, cookies):
            self.status_label.config(text="Website is compatible. Proceeding with the test.")
            self.process_payload_sleep_post(url, endpoint, data, cookies)
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
