#! /usr/bin/env python3
# Written by Rupe version 3.0
#
"""
Tor Iptables script is an anonymizer
that sets up iptables and tor to route all services
and traffic including DNS through the tor network.
"""

from subprocess import call, check_call, CalledProcessError
from os.path import isfile, basename
from os import devnull
from sys import exit
from atexit import register
from argparse import ArgumentParser
from json import load
from urllib.request import urlopen
from urllib.error import URLError
from time import sleep
import re

class TorIptables:

    def __init__(self):
        self.local_dnsport = "53"  # DNSPort
        self.virtual_net = "10.0.0.0/10"  # VirtualAddrNetwork
        self.local_loopback = "127.0.0.1"  # Local loopback
        self.non_tor_net = ["192.168.0.0/16", "172.16.0.0/12"]
        self.non_tor = ["127.0.0.0/9", "127.128.0.0/10", "127.0.0.0/8"]
        self.tor_uid = self.get_tor_uid()  # Tor user uid
        self.trans_port = "9040"  # Tor port
        self.tor_config_file = '/etc/tor/torrc'
        self.torrc = f'''
## Inserted by {basename(__file__)} for tor iptables rules set
## Transparently route all traffic thru tor on port {self.trans_port}
VirtualAddrNetwork {self.virtual_net}
AutomapHostsOnResolve 1
TransPort {self.trans_port}
DNSPort {self.local_dnsport}
'''

    def get_tor_uid(self):
        try:
            from subprocess import check_output
            return check_output(["id", "-ur", "debian-tor"]).decode().strip()
        except CalledProcessError:
            exit("Failed to get 'debian-tor' user ID. Ensure that Tor is installed and that the 'debian-tor' user exists.")

    def flush_iptables_rules(self):
        call(["iptables", "-F"])
        call(["iptables", "-t", "nat", "-F"])

    def load_iptables_rules(self):
        self.flush_iptables_rules()
        self.non_tor.extend(self.non_tor_net)

        @register
        def restart_tor():
            fnull = open(devnull, 'w')
            try:
                tor_restart = check_call(
                    ["service", "tor", "restart"],
                    stdout=fnull, stderr=fnull)
                if tor_restart == 0:
                    print(" [\033[92m+\033[0m] Anonymizer status \033[92m[ON]\033[0m")
                    self.get_ip()
            except CalledProcessError as err:
                print(f"\033[91m[!] Command failed: {' '.join(err.cmd)}\033[0m")

        call(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d",
              self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp",
              "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP"])
        call(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d",
              self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp",
              "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP"])

        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner",
              self.tor_uid, "-j", "RETURN"])
        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport",
              self.local_dnsport, "-j", "REDIRECT", "--to-ports", self.local_dnsport])

        for net in self.non_tor:
            call(["iptables", "-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])

        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j",
              "REDIRECT", "--to-ports", self.trans_port])

        call(["iptables", "-A", "OUTPUT", "-m", "state", "--state",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"])

        for net in self.non_tor:
            call(["iptables", "-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])

        call(["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", self.tor_uid, "-j", "ACCEPT"])
        call(["iptables", "-A", "OUTPUT", "-j", "REJECT"])

    def get_ip(self):
        print(" [\033[92m*\033[0m] Getting public IP, please wait...")
        retries = 0
        my_public_ip = None
        while retries < 12 and not my_public_ip:
            retries += 1
            try:
                my_public_ip = load(urlopen('https://check.torproject.org/api/ip'))['IP']
            except URLError:
                sleep(5)
                print(" [\033[93m?\033[0m] Still waiting for IP address...")
            except ValueError:
                break
        if not my_public_ip:
            my_public_ip = self.getoutput('wget -qO - ident.me')
        if not my_public_ip:
            exit(" \033[91m[!]\033[0m Can't get public IP address!")
        print(f" [\033[92m+\033[0m] Your IP is \033[92m{my_public_ip}\033[0m")

    def getoutput(self, cmd):
        try:
            from subprocess import check_output
            return check_output(cmd.split()).decode().strip()
        except CalledProcessError:
            return None

if __name__ == '__main__':
    parser = ArgumentParser(
        description='Tor Iptables script for loading and unloading iptables rules')
    parser.add_argument('-l', '--load', action='store_true', help='This option will load tor iptables rules')
    parser.add_argument('-f', '--flush', action='store_true', help='This option flushes the iptables rules to default')
    parser.add_argument('-r', '--refresh', action='store_true', help='This option will change the circuit and gives new IP')
    parser.add_argument('-i', '--ip', action='store_true', help='This option will output the current public IP address')
    args = parser.parse_args()

    try:
        load_tables = TorIptables()
        if isfile(load_tables.tor_config_file):
            if 'VirtualAddrNetwork' not in open(load_tables.tor_config_file).read():
                with open(load_tables.tor_config_file, 'a+') as torrconf:
                    torrconf.write(load_tables.torrc)

        if args.load:
            load_tables.load_iptables_rules()
        elif args.flush:
            load_tables.flush_iptables_rules()
            print(" [\033[93m!\033[0m] Anonymizer status \033[91m[OFF]\033[0m")
        elif args.ip:
            load_tables.get_ip()
        elif args.refresh:
            call(['kill', '-HUP', load_tables.getoutput('pidof tor')])
            load_tables.get_ip()
        else:
            parser.print_help()
    except Exception as err:
        print(f"[!] Run as super user: {str(err)}")
