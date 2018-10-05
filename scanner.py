import argparse
from scapy.all import *
import re
import ipaddress
from collections import namedtuple

parser = argparse.ArgumentParser(description='Custom Port Scanner')
parser.add_argument('hosts', help='hosts to be scanned seperated by commas. Accepts single ips, ranges seperated by "-" and cidr')
parser.add_argument('-p', '--ports', help='ports to be scanned. Defaults to common ports 1-1024')
parser.add_argument('--tcp', help='scan tcp ports. Defaults to true')
parser.add_argument('--udp', help='scan udp ports')
parser.add_argument('--timeout', help='timeout in seconds for all functions. Default 5 sec')
parser.add_argument('-v','--verbose', help='verbose output', action='store_true')
args = parser.parse_args()

def scan_tcp(hosts, ports, args):
    return

def scan_udp(hosts, ports, args):
    return

def parse_hosts(host_args, args):
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

def parse_ports(port_args, args):
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

def parse_extra_args(args):
    extra_args = namedtuple('args', ['verbose', 'tcp', 'udp'])
    extra_args.timeout = 5 if not args.timeout else int(args.timeout)
    extra_args.verbose = True if args.verbose else False
    extra_args.tcp = False if not args.tcp else True
    extra_args.udp = True if args.udp else False
    return extra_args

def ping_hosts(hosts, args):
    hosts_alive = list()
    hosts_down = list()
    for host in hosts:
        packet = IP(dst=host)/ICMP()
        ans, unans = sr(packet, timeout=args.timeout, verbose=args.verbose)
        for answered in ans:
            hosts_alive.append(answered[1].src)
        for unanswered in unans:
            hosts_down.append(unanswered[0].dst)
    return hosts_alive, hosts_down

print("Starting scanner ...")
extra_args = parse_extra_args(args)
hosts = parse_hosts(args.hosts, extra_args)
ports = parse_ports(args.ports, extra_args)
print("Starting ping sweep ...")
hosts_alive, hosts_down = ping_hosts(hosts, extra_args)
print("Found %d alive hosts" % len(hosts_alive))

if extra_args.verbose:
    print("Alive hosts: %s" % hosts_alive)

print("Found %d down hosts " % len(hosts_down))

if extra_args.verbose:
    print("Down hosts: %s" % hosts_down)

print("Continuing with alive hosts ...")

if extra_args.tcp:
    print("Starting tcp scan ...")
    scan_tcp(hosts_alive, ports, extra_args)
if extra_args.udp:
    print("Starting udp scan ...")
    scan_udp(hosts_alive, ports, extra_args)