import requests
from urllib.parse import urlparse, parse_qs
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import logging
import time

# Configuration
LOG = 1
DISPLAY_PACKETS = True
MAX_RETRIES = 3
PAYLOADS_FILE_PATH = 'SQL-Time.txt'

# Setup logging
logging.basicConfig(filename='sql_injection_tool.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def post_processor(request_file_content):
    lines = request_file_content.splitlines()
    if not lines:
        return None, None, None, None

    method, path, _ = lines[0].split()
    if method != "POST":
        raise ValueError("Only POST requests are supported.")

    url = urlparse(path).scheme + "://" + urlparse(path).netloc
    endpoint = path

    post_data = {}
    content_length = None
    for line in lines:
        if line.startswith("Content-Length:"):
            content_length = int(line.split(":")[1].strip())
            break

    if content_length is not None:
        post_data_index = lines.index(f"Content-Length: {content_length}") + 1
        post_data = "\n".join(lines[post_data_index:post_data_index + content_length]).strip()
        post_data = dict(parse_qs(post_data))
        post_data = {key: value[0] for key, value in post_data.items()}

    cookies = {}
    for line in lines:
        if line.startswith("Cookie:"):
            cookie_str = line.split(":", 1)[1].strip()
            cookies = dict(parse_qs(cookie_str))
            cookies = {key: value[0] for key, value in cookies.items()}
            break

    return url, endpoint, post_data, cookies

def get_solution_for_status_code(status_code):
    solutions = {
        400: "Bad Request - Ensure request parameters and syntax are correct.",
        401: "Unauthorized - Verify credentials or API key.",
        403: "Forbidden - Check permissions or API limits.",
        404: "Not Found - Verify URL or endpoint.",
        500: "Internal Server Error - Check server logs.",
        502: "Bad Gateway - Try again later.",
        503: "Service Unavailable - Try again later.",
        504: "Gateway Timeout - Check server status or try again later."
    }
    return solutions.get(status_code, "Unknown error. Check server logs.")

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
        self.enabled = True

    def show_tooltip(self, event=None):
        if not self.enabled or not self.text:
            return
        if self.tooltip_window:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 20
        y += self.widget.winfo_rooty() + 20
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip_window, text=self.text, background="lightyellow", relief="solid", borderwidth=1, padx=5, pady=5)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class SQLInjectionTool:
    def __init__(self, master):
        self.master = master
        self.master.title("SQL Injection Tool")

        self.payloads = []
        self.payloads_path = PAYLOADS_FILE_PATH
        self.post_data = None
        self.endpoint = None
        self.cookies = None
        self.tooltips_enabled = True

        # Create the ribbon menu
        self.menu_bar = tk.Menu(master)
        master.config(menu=self.menu_bar)

        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)
        self.settings_menu.add_command(label="Disable Tooltips", command=self.toggle_tooltips)
        self.settings_menu.add_command(label="Toggle Display Packets", command=self.toggle_packets)

        # Frame for main controls
        self.control_frame = tk.Frame(master, padx=10, pady=10)
        self.control_frame.grid(row=0, column=0, sticky='nsew')

        # Title
        self.title_label = tk.Label(self.control_frame, text="SQL Injection Testing Tool", font=("Arial", 14))
        self.title_label.grid(row=0, column=0, columnspan=2, pady=5)

        # Upload Request File
        self.upload_button = tk.Button(self.control_frame, text="Upload Request File", command=self.upload_request_file)
        self.upload_button.grid(row=1, column=0, pady=5, sticky='ew')
        self.upload_tooltip = ToolTip(self.upload_button, "Select the file containing the HTTP request.")

        # Upload Payloads File
        self.upload_payload_button = tk.Button(self.control_frame, text="Upload Payloads File", command=self.load_payload_file)
        self.upload_payload_button.grid(row=1, column=1, pady=5, padx=5, sticky='ew')
        self.upload_payload_tooltip = ToolTip(self.upload_payload_button, "Select the file containing the payloads.")

        # Host and Endpoint
        self.host_endpoint_label = tk.Label(self.control_frame, text="Host and Endpoint:")
        self.host_endpoint_label.grid(row=2, column=0, sticky='w', pady=5)

        self.host_endpoint_entry = tk.Entry(self.control_frame, width=50)
        self.host_endpoint_entry.grid(row=2, column=1, pady=5, sticky='ew')
        self.host_endpoint_tooltip = ToolTip(self.host_endpoint_entry, "Enter the URL and endpoint for the POST request.")

        # POST Parameters
        self.param_label = tk.Label(self.control_frame, text="POST Parameters:")
        self.param_label.grid(row=3, column=0, sticky='w', pady=5)

        self.param_entry = tk.Entry(self.control_frame, width=50)
        self.param_entry.grid(row=3, column=1, pady=5, sticky='ew')
        self.param_tooltip = ToolTip(self.param_entry, "Enter the POST parameters in key=value format.")

        # Cookies
        self.cookie_label = tk.Label(self.control_frame, text="Cookies (optional):")
        self.cookie_label.grid(row=4, column=0, sticky='w', pady=5)

        self.cookie_entry = tk.Entry(self.control_frame, width=50)
        self.cookie_entry.grid(row=4, column=1, pady=5, sticky='ew')
        self.cookie_tooltip = ToolTip(self.cookie_entry, "Enter cookies if required.")

        # Payload Handling Options
        self.payload_frame = tk.LabelFrame(self.control_frame, text="Payload Handling Options", padx=10, pady=10)
        self.payload_frame.grid(row=5, column=0, columnspan=2, pady=10, padx=5, sticky='ew')

        self.payload_options = ["Combine Payloads", "Split Payloads"]
        self.selected_payload_option = tk.StringVar()
        self.selected_payload_option.set(self.payload_options[0])

        self.payload_menu = tk.OptionMenu(self.payload_frame, self.selected_payload_option, *self.payload_options, command=self.update_split_payload_options)
        self.payload_menu.pack(pady=5, fill='x')
        self.payload_tooltip = ToolTip(self.payload_menu, "Choose how to handle payloads.")

        # Frame for split payload options (initially hidden)
        self.split_payload_option_frame = tk.Frame(self.payload_frame)
        self.split_payload_option_frame.pack_forget()

        self.split_payload_option = tk.StringVar()
        self.split_payload_option.set("URL Payloads")

        self.split_payload_menu = tk.OptionMenu(self.split_payload_option_frame, self.split_payload_option, "URL Payloads", "POST Data Payloads")
        self.split_payload_menu.pack(pady=5)
        self.split_payload_tooltip = ToolTip(self.split_payload_menu, "Select type of payload for split options.")

        # Progress Bar and Time Estimate
        self.progress_frame = tk.Frame(master, padx=10, pady=5)
        self.progress_frame.grid(row=1, column=0, pady=10, sticky='ew')

        self.progress = ttk.Progressbar(self.progress_frame, orient="horizontal", length=550, mode="determinate")
        self.progress.pack(side=tk.LEFT, pady=5, fill='x', expand=True)

        self.time_label = tk.Label(self.progress_frame, text="Elapsed Time: N/A")
        self.time_label.pack(side=tk.LEFT, pady=5)

        self.start_testing_button = tk.Button(self.progress_frame, text="▶", command=self.start_testing_thread, font=("Arial", 12), width=3)
        self.start_testing_button.pack(side=tk.RIGHT, padx=5)
        self.test_tooltip = ToolTip(self.start_testing_button, "Start testing with the selected payloads.")

        # Status and Log
        self.status_frame = tk.Frame(master, padx=10, pady=10)
        self.status_frame.grid(row=2, column=0, pady=10, sticky='ew')

        self.status_label = tk.Label(self.status_frame, text="Status: N/A")
        self.status_label.pack(pady=5)

        self.log_text = tk.Text(self.status_frame, height=20, wrap="word")
        self.log_text.pack(pady=5, fill='both', expand=True)
        self.log_tooltip = ToolTip(self.log_text, "Log area for displaying test results and errors.")

        # Configure grid rows and columns to expand
        self.control_frame.grid_rowconfigure(5, weight=1)
        self.control_frame.grid_columnconfigure(0, weight=1)
        self.control_frame.grid_columnconfigure(1, weight=1)

        self.master.grid_rowconfigure(0, weight=0)
        self.master.grid_rowconfigure(1, weight=0)
        self.master.grid_rowconfigure(2, weight=1)
        self.master.grid_columnconfigure(0, weight=1)

        # Initialize
        self.update_split_payload_options(None)

    def toggle_tooltips(self):
        if self.tooltips_enabled:
            self.upload_tooltip.disable()
            self.upload_payload_tooltip.disable()
            self.host_endpoint_tooltip.disable()
            self.param_tooltip.disable()
            self.cookie_tooltip.disable()
            self.packet_tooltip.disable()
            self.payload_tooltip.disable()
            self.split_payload_tooltip.disable()
            self.test_tooltip.disable()
            self.settings_menu.entryconfig("Disable Tooltips", label="Enable Tooltips")
        else:
            self.upload_tooltip.enable()
            self.upload_payload_tooltip.enable()
            self.host_endpoint_tooltip.enable()
            self.param_tooltip.enable()
            self.cookie_tooltip.enable()
            self.packet_tooltip.enable()
            self.payload_tooltip.enable()
            self.split_payload_tooltip.enable()
            self.test_tooltip.enable()
            self.settings_menu.entryconfig("Enable Tooltips", label="Disable Tooltips")
        self.tooltips_enabled = not self.tooltips_enabled

    def toggle_packets(self):
        global DISPLAY_PACKETS
        DISPLAY_PACKETS = not DISPLAY_PACKETS
        self.settings_menu.entryconfig("Toggle Display Packets", label="Hide Display Packets" if DISPLAY_PACKETS else "Show Display Packets")

    def upload_request_file(self):
        file_path = filedialog.askopenfilename(title="Select Request File")
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.url, self.endpoint, self.post_data, self.cookies = post_processor(content)
                    self.host_endpoint_entry.delete(0, tk.END)
                    self.host_endpoint_entry.insert(0, self.url + self.endpoint)
                    if self.post_data:
                        post_data_str = '&'.join([f"{key}={value}" for key, value in self.post_data.items()])
                        self.param_entry.delete(0, tk.END)
                        self.param_entry.insert(0, post_data_str)
                    if self.cookies:
                        cookies_str = '&'.join([f"{key}={value}" for key, value in self.cookies.items()])
                        self.cookie_entry.delete(0, tk.END)
                        self.cookie_entry.insert(0, cookies_str)
            except Exception as e:
                logging.error(f"Error reading request file: {e}")
                messagebox.showerror("Error", f"Error reading request file: {e}")

    def load_payload_file(self):
        file_path = filedialog.askopenfilename(title="Select Payloads File")
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.payloads = file.read().splitlines()
            except Exception as e:
                logging.error(f"Error reading payloads file: {e}")
                messagebox.showerror("Error", f"Error reading payloads file: {e}")

    def update_split_payload_options(self, selected_option):
        if selected_option == "Split Payloads":
            self.split_payload_option_frame.pack(pady=5, fill='x')
        else:
            self.split_payload_option_frame.pack_forget()

    def start_testing_thread(self):
        thread = threading.Thread(target=self.start_testing)
        thread.start()

    def start_testing(self):
        self.progress["value"] = 0
        self.status_label.config(text="Status: Running")
        self.log_text.delete(1.0, tk.END)
        start_time = time.time()

        for payload in self.payloads:
            if self.selected_payload_option.get() == "Split Payloads":
                payload_parts = [payload[i:i + len(payload) // 2] for i in range(0, len(payload), len(payload) // 2)]
                payloads_to_test = payload_parts
            else:
                payloads_to_test = [payload]

            for p in payloads_to_test:
                if self.url:
                    self.test_payload(p)

        elapsed_time = time.time() - start_time
        self.time_label.config(text=f"Elapsed Time: {elapsed_time:.2f} seconds")
        self.status_label.config(text="Status: Complete")

    def test_payload(self, payload):
        try:
            if self.selected_payload_option.get() == "Split Payloads":
                if self.split_payload_option.get() == "URL Payloads":
                    full_url_with_payload = f"{self.url}{self.endpoint}?{payload}"
                    r = requests.get(full_url_with_payload, cookies=self.cookies)
                elif self.split_payload_option.get() == "POST Data Payloads":
                    data_with_payload = {key: value + payload for key, value in self.post_data.items()}
                    r = requests.post(f"{self.url}{self.endpoint}", data=data_with_payload, cookies=self.cookies)
            else:
                if self.endpoint:
                    full_url_with_payload = f"{self.url}{self.endpoint}?{payload}"
                    r = requests.get(full_url_with_payload, cookies=self.cookies)
                else:
                    data_with_payload = {key: value + payload for key, value in self.post_data.items()}
                    r = requests.post(self.url, data=data_with_payload, cookies=self.cookies)

            if DISPLAY_PACKETS:
                self.log_text.insert(tk.END, f"Testing payload: {payload}\n")
                self.log_text.insert(tk.END, f"URL: {r.url}\n")
                self.log_text.insert(tk.END, f"Status Code: {r.status_code}\n")
                self.log_text.insert(tk.END, f"Response: {r.text}\n")
                self.log_text.insert(tk.END, "-"*80 + "\n")

            if r.status_code != 200:
                solution = get_solution_for_status_code(r.status_code)
                self.log_text.insert(tk.END, f"Suggested Solution: {solution}\n")

            self.progress["value"] += (100 / len(self.payloads))

        except requests.RequestException as e:
            logging.error(f"Request failed: {e}")
            self.log_text.insert(tk.END, f"Error testing payload {payload}: {e}\n")

# Create and run the application
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x600")  # Set a compact window size
    app = SQLInjectionTool(root)
    root.mainloop()
