import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import time
import requests

class SQLInjectionTester(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SQL Injection Tester")
        self.geometry("500x500")

        # Initializing variables
        self.payloads_path = None

        # Creating GUI components
        tk.Label(self, text="SQL Injection Tester", font=("Helvetica", 16)).pack(pady=10)

        # Payload handling option
        self.payload_option_var = tk.StringVar(value="Combine Payloads")
        options = ["Combine Payloads", "Split Payloads", "URL Payloads", "Username POST Data Payloads"]
        tk.Label(self, text="Payload Handling Option:").pack(pady=10)
        self.payload_option_menu = ttk.Combobox(self, textvariable=self.payload_option_var, values=options, state="readonly")
        self.payload_option_menu.pack(pady=10)

        # URL and endpoint inputs
        tk.Label(self, text="URL:").pack(pady=5)
        self.url_entry = tk.Entry(self, width=50)
        self.url_entry.pack(pady=5)

        tk.Label(self, text="Endpoint:").pack(pady=5)
        self.endpoint_entry = tk.Entry(self, width=50)
        self.endpoint_entry.pack(pady=5)

        # POST data input
        tk.Label(self, text="POST Data (e.g., 'username=admin&password=pass'):").pack(pady=5)
        self.post_data_entry = tk.Entry(self, width=50)
        self.post_data_entry.pack(pady=5)

        # Cookies input
        tk.Label(self, text="Cookies (optional):").pack(pady=5)
        self.cookies_entry = tk.Entry(self, width=50)
        self.cookies_entry.pack(pady=5)

        # File selection button
        self.select_file_btn = tk.Button(self, text="Select Payloads File", command=self.select_payload_file)
        self.select_file_btn.pack(pady=10)

        # Progress bar and status label
        self.progress = ttk.Progressbar(self, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10)

        self.time_label = tk.Label(self, text="Estimated Time Remaining: N/A")
        self.time_label.pack(pady=5)

        self.status_label = tk.Label(self, text="Status: Waiting for input.")
        self.status_label.pack(pady=5)

        # Start button
        self.start_button = tk.Button(self, text="Start Testing", command=self.start_testing)
        self.start_button.pack(pady=10)

        # Log box
        self.log_box = tk.Text(self, height=10, width=60)
        self.log_box.pack(pady=10)

    def log_message(self, message):
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)

    def select_payload_file(self):
        self.payloads_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.payloads_path:
            self.log_message(f"Selected payloads file: {self.payloads_path}")
            self.status_label.config(text="Payloads file selected.")
        else:
            self.log_message("No payloads file selected.")
            self.status_label.config(text="No payloads file selected.")

    def start_testing(self):
        url = self.url_entry.get().strip()
        endpoint = self.endpoint_entry.get().strip()
        post_data = self.post_data_entry.get().strip()
        cookies = self.cookies_entry.get().strip()

        if not url or not endpoint or not post_data:
            messagebox.showerror("Input Error", "Please fill out the URL, endpoint, and POST data fields.")
            return

        # Parse POST data into a dictionary
        post_data_dict = dict(x.split('=') for x in post_data.split('&'))

        # Start the SQL injection testing process
        self.process_payload_sleep_post(url, endpoint, post_data_dict, cookies)

    def process_payload_sleep_post(self, url, endpoint, data, cookies):
        """
        Processes the payloads from the file and tests for SQL injection vulnerabilities.
        Payloads will be applied according to the selected option.
        """
        if not self.payloads_path or not os.path.isfile(self.payloads_path):
            self.status_label.config(text="No payloads file selected or the file does not exist.")
            return

        try:
            with open(self.payloads_path, 'r') as f:
                payloads = f.readlines()
        except Exception as e:
            self.log_message(f"Error reading payloads file: {e}")
            return

        total_payloads = len(payloads)
        self.progress["maximum"] = total_payloads

        if not self.check_compatibility(url, endpoint, data, cookies):
            self.log_message("The website did not return an expected response with test payload. Aborting.")
            return

        start_time = time.time()
        for i, payload in enumerate(payloads):
            payload = payload.strip()

            # Handling payload application based on the selected option
            option = self.payload_option_var.get()

            if option == "Combine Payloads":
                # Apply the same payload to both URL and username POST data
                data_with_payload = {key: payload if key == 'username' else value + payload for key, value in data.items()}
                endpoint_with_payload = f"{endpoint}?username={payload}"

            elif option == "Split Payloads":
                # Apply different payloads for URL and username POST data
                url_payload = payload + "_url"
                post_payload = payload + "_post"
                data_with_payload = {key: post_payload if key == 'username' else value + post_payload for key, value in data.items()}
                endpoint_with_payload = f"{endpoint}?username={url_payload}"

            elif option == "URL Payloads":
                # Apply payloads only to the URL
                endpoint_with_payload = f"{endpoint}?username={payload}"
                data_with_payload = data  # No changes to POST data

            elif option == "Username POST Data Payloads":
                # Apply payloads only to the username POST data
                data_with_payload = {key: payload if key == 'username' else value for key, value in data.items()}
                endpoint_with_payload = endpoint  # No changes to URL

            r, url_test = self.get_request_send(url, endpoint_with_payload, data_with_payload, cookies)
            if r:
                self.log_message(f"Testing with payload: {payload}")
                if "delay" in r.text or r.elapsed.total_seconds() > 5:
                    self.log_message(f"Possible SQL injection vulnerability detected with payload: {payload}")
            else:
                self.log_message(f"Failed to send payload: {payload}")

            self.progress["value"] = i + 1
            elapsed_time = time.time() - start_time
            estimated_total_time = (elapsed_time / (i + 1)) * total_payloads
            remaining_time = estimated_total_time - elapsed_time
            self.time_label.config(text=f"Estimated Time Remaining: {int(remaining_time)}s")
            self.master.update_idletasks()

        self.log_message("SQL Injection Testing Complete.")
        self.status_label.config(text="Testing completed. Check logs for details.")

    def get_request_send(self, url, endpoint, data, cookies):
        """Handles the request sending."""
        try:
            full_url = f"{url}/{endpoint}"
            headers = {'Cookie': cookies} if cookies else {}
            r = requests.post(full_url, data=data, headers=headers)
            return r, full_url
        except requests.RequestException as e:
            self.log_message(f"Error sending request to {url}: {e}")
            return None, None

    def check_compatibility(self, url, endpoint, data, cookies):
        """Checks if the website responds as expected with a test payload."""
        test_payload = "test_payload"
        test_endpoint = f"{endpoint}?username={test_payload}"
        test_data = {key: test_payload if key == 'username' else value for key, value in data.items()}
        r, _ = self.get_request_send(url, test_endpoint, test_data, cookies)
        return r is not None

if __name__ == "__main__":
    app = SQLInjectionTester()
    app.mainloop()
