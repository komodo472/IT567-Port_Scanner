import argparse
from scapy.all import *
import re
import ipaddress
from collections import namedtuple
import pprint
from fpdf import FPDF

parser = argparse.ArgumentParser(description='Custom Port Scanner')
parser.add_argument('hosts', help='hosts to be scanned seperated by commas. Accepts single ips, ranges seperated by "-" and cidr')
parser.add_argument('-p', '--ports', help='ports to be scanned. Defaults to common ports 1-1024')
parser.add_argument('-f', '--file', help='read hosts from file')
parser.add_argument('--pdf', help='output to pdf with given name')
parser.add_argument('--tcp', help='scan tcp ports. Defaults to true')
parser.add_argument('--tcp-timeout', help='timeout in seconds for tcp scan. Default 5 sec')
parser.add_argument('--udp', help='scan udp ports')
parser.add_argument('--udp-timeout', help='timeout in seconds for udp scan. Default 5 sec')
parser.add_argument('--udp-interval', help='interval in seconds between sending udp packets. Default 0 sec. WARNING! This option can take a really long time if changed. Longer interval will provide better results')
parser.add_argument('--udp-retry', help='number of time to resend unanswered packetes for udp scan. Defaults to 1')
parser.add_argument('--ping-timeout', help='timeout in seconds for ping sweep. Default 5 sec')
parser.add_argument('-v','--verbose', help='verbose output', action='store_true')
args = parser.parse_args()

conf.L3socket=L3RawSocket

def scan_tcp(hosts, ports, args):
    host_res = {}
    for host in hosts:
        source_port = RandShort()
        packet = IP(dst=host)/TCP(sport=source_port, dport=ports, flags='S')
        ans, unans = sr(packet, timeout=args.tcp_timeout, verbose=args.verbose)
        open_ports = list()
        for answered in ans:
            if answered[1][1].flags == 'SA':
                open_ports.append(int(answered[1].sport))
        sr(IP(dst=host)/TCP(sport=source_port, dport=open_ports, flags='R'), timeout=args.tcp_timeout, verbose=args.verbose)
        if len(open_ports) != 0:
            host_res[host] = open_ports
    return host_res

def scan_udp(hosts, ports, args):
    host_res = {}
    for host in hosts:
        open_ports = list()
        #for port in ports:
        source_port = RandShort()
        packet = IP(dst=host)/UDP(sport=source_port, dport=ports)
        ans, unans = sr(packet, timeout=args.udp_timeout, verbose=args.verbose, inter=args.udp_interval, retry=args.udp_retry)
        """for answered in ans:
            if hasattr(answered[1][1], 'type') and hasattr(answered[1][1], 'code') and answered[1][1].type == 3 and answered[1][1].code == 3:
                print("Port closed: %d" % int(answered[1].dport))
            else:
                print("Unkown response")"""
        for unanswered in unans:
            #print("Port open: %s" % )
            port = int(unanswered[1].default_fields['dport'])
            if port not in open_ports:
                open_ports.append(port)
        if len(open_ports) != 0:
            host_res[host] = open_ports
    return host_res

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

def parse_file(host_file, args):
    hosts = list()
    with open(host_file, 'r') as file:
        for line in file:
            hosts += parse_hosts(line.strip(), args)
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
    extra_args = namedtuple('args', ['verbose', 'tcp_timeout', 'udp_timeout', 'udp_interval', 'udp_retry', 'ping_timeout', 'tcp', 'udp'])
    extra_args.tcp_timeout = 5 if not args.tcp_timeout else int(args.tcp_timeout)
    extra_args.udp_timeout = 5 if not args.udp_timeout else int(args.udp_timeout)
    extra_args.udp_interval = 0 if not args.udp_interval else int(args.udp_interval)
    extra_args.udp_retry = 1 if not args.udp_retry else int(args.udp_retry)
    extra_args.ping_timeout = 5 if not args.ping_timeout else int(args.ping_timeout)
    extra_args.verbose = True if args.verbose else False
    extra_args.tcp = False if args.tcp and args.tcp == 'False' else True
    extra_args.udp = True if args.udp and args.udp == 'True' else False
    return extra_args

def ping_hosts(hosts, args):
    hosts_alive = list()
    hosts_down = list()
    for host in hosts:
        packet = IP(dst=host)/ICMP()
        ans, unans = sr(packet, timeout=args.ping_timeout, verbose=args.verbose)
        for answered in ans:
            hosts_alive.append(answered[1].src)
        for unanswered in unans:
            hosts_down.append(unanswered[0].dst)
    return hosts_alive, hosts_down

def make_pdf(name, tcp_ports, udp_ports):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Courier', 'I', 14)
    pdf.set_draw_color(255, 255, 255)
    effective_page_width = pdf.w - 2*pdf.l_margin
    pdf.cell(40,10, 'Open TCP Ports:')
    pdf.ln()
    for host in tcp_ports:
        pdf.cell(40,10,host)
        pdf.ln()
        pdf.cell(40,10, str(tcp_ports[host]))
        pdf.ln()
    pdf.ln()
    pdf.cell(40,10, 'Open UDP Ports:')
    pdf.ln()
    for host in udp_ports:
        pdf.cell(40,10,host)
        pdf.ln()
        pdf.cell(40,10, str(udp_ports[host]))
        pdf.ln()
    pdf.output(name + '.pdf')

print("Starting scanner ...")
extra_args = parse_extra_args(args)
hosts = parse_hosts(args.hosts, extra_args)
if args.file:
    file_hosts = parse_file(args.file, args)
    hosts += file_hosts
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

if len(hosts_alive) == 0:
    print("No alive hosts. Terminating")
    exit(0)

pp = pprint.PrettyPrinter(indent=4)
open_tcp_ports = dict()
if extra_args.tcp:
    print("Starting tcp scan ...")
    open_tcp_ports = scan_tcp(hosts_alive, ports, extra_args)
    pp.pprint(open_tcp_ports)
open_udp_ports = dict()
if extra_args.udp:
    print("Starting udp scan ...")
    open_udp_ports = scan_udp(hosts_alive, ports, extra_args)
    pp.pprint(open_udp_ports)

if args.pdf:
    print("Making pdf with name %s.pdf" % args.pdf)
    make_pdf(args.pdf, open_tcp_ports, open_udp_ports)