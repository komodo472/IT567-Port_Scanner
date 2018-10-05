# IT567-Port_Scanner

## Installation
run `pip3 install -r requirements.txt` to install required pip packages

## Running program

Run `python3 scanner.py` to run the program

### The following are examples of how to run the program
Basic scan:  
`python3 scanner.py 192.168.207.41`

Using different ports:  
`python3 scanner.py 192.168.207.41 -p 10-34`

Range of hosts:  
`python3 scanner.py 192.168.207.41-192.168.207.42`

Using file for hosts:  
`python3 scanner.py 192.168.207.41 --f ips.txt`

Add UDP to scan:  
`python3 scanner.py 192.168.207.41 -p 10-34 --udp True`

Generate pdf:  
`python3 scanner.py 192.168.207.41 -p 10-34 --pdf results`
