##
# Connects to the device on port 389 and obtains the vendor, hostname, and firmware version.
# The script should work on a number of vendors but Crestron seems to be the most popular.
#
# Sample usage:
# 
# albinolobster@ubuntu:~/poc/crestron$ python wppcmd_version.py -i 192.168.1.88
# [+] Attempting connection to 192.168.1.88:389
# [+] Connected!
# 192.168.1.88,AirMedia-352,Crestro,2.7.0.1
#
##
import argparse
import socket
import struct
import sys
import time
 
top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('-i', '--ip', action="store", dest="ip", required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port", type=int, help="The port to connect to", default="389")
args = top_parser.parse_args()


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
print "[+] Attempting connection to " + args.ip + ":" + str(args.port)
sock.connect((args.ip, args.port))
print "[+] Connected!"
 
wppcmd = "wppcmd\x00\x00\x90"
sock.sendall(wppcmd)
 
resp = sock.recv(1024)

if len(resp) == 0x89 and resp.startswith("wppcmd\x00\x00\x91AWPP") == True:
	ip = resp[0x0d:0x12]
	hostname = resp[0x19:0x41]
	hostname = hostname.strip()
	brand = resp[0x41:0x48]
	brand = brand.strip()
	version = resp[0x7b:0x7f]
	converted_ip = str(ord(ip[0])) + '.' + \
				   str(ord(ip[1])) + '.' + \
				   str(ord(ip[2])) + '.' + \
				   str(ord(ip[3]))
	converted_version = str(ord(version[0])) + '.' + \
						str(ord(version[1])) + '.' + \
						str(ord(version[2])) + '.' + \
						str(ord(version[3]))
 
 	print converted_ip + "," + hostname + "," + brand + "," + converted_version

sock.close()