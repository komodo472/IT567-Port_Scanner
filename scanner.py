import argparse

parser = argparse.ArgumentParser(description='Custom Port Scanner')
parser.add_argument('hosts', help='hosts to be scanned')
parser.add_argument('-p', '--ports', help='ports to be scanned. Defaults to common ports 0-1024')
parser.add_argument('--tcp', help='scan tcp ports. Defaults to tcp')
parser.add_argument('--udp', help='scan udp ports')
parser.parse_args()

def scan_tcp(hosts, ports):
    return

def scan_udp(hosts, ports):
    return

def parse_hosts(host_args):
    return

def parse_ports(port_args):
    return