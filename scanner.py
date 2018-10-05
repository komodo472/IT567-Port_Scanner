import argparse
from scapy.all import *
import re
import ipaddress

parser = argparse.ArgumentParser(description='Custom Port Scanner')
parser.add_argument('hosts', help='hosts to be scanned seperated by commas. Accepts single ips, ranges seperated by "-" and cidr')
parser.add_argument('-p', '--ports', help='ports to be scanned. Defaults to common ports 1-1024')
parser.add_argument('--tcp', help='scan tcp ports. Defaults to tcp')
parser.add_argument('--udp', help='scan udp ports')
args = parser.parse_args()

def scan_tcp(hosts, ports):
    return

def scan_udp(hosts, ports):
    return

def parse_hosts(host_args):
    host_list = host_args.split(',')
    hosts = list()
    for host in host_list:
        if re.match(r'.*-.*', host):
            host_range = host.split('-')
            host_addrs = [str(ipaddr) for ipaddr in ipaddress.summarize_address_range( ipaddress.IPv4Address(host_range[0]), ipaddress.IPv4Address(host_range[1]))]
            hosts += host_addrs
        else:
            hosts.append(host)
    return hosts

def parse_ports(port_args):
    if not port_args:
        return list(range(1, 1024))
    port_list = port_args.split(',')
    ports = list()
    for port in port_list:
        if re.match(r'.*-.*', port):
            port_range = port.split('-')
            for new_port in range(int(port_range[0]), int(port_range[1]) + 1):
                ports.append(new_port)
        else:
            ports.append(port)
    return ports

hosts = parse_hosts(args.hosts)
ports = parse_ports(args.ports)

print(hosts)
print(ports)