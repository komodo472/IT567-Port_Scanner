import argparse

parser = argparse.ArgumentParser(description='Custom Port Scanner')
parser.add_argument('hosts', help='hosts to be scanned')
parser.add_argument('-p', '--ports', help='ports to be scanned. Defaults to common ports 0-1024')
parser.parse_args()
