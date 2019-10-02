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
import select

top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('-i', '--ip', action="store", dest="ip", required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port", type=int, help="The port to connect to", default="389")
args = top_parser.parse_args()


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
print ("[+] Attempting connection to " + args.ip + ":" + str(args.port))
sock.connect((args.ip, args.port))
print ("[+] Connected!")

wppcmd = bytes('wppcmd', 'utf-8') + bytes.fromhex('000090')
sock.setblocking(0)
sock.sendall(wppcmd)

ready = select.select([sock], [], [], 5)

if ready[0]:
	resp = sock.recv(1024)

	if len(resp) == 0x89 and resp.startswith(bytes("wppcmd", 'utf-8')) == True:
		ip = resp[0x0d:0x12]
		hostname = resp[0x19:0x41]
		hostname = hostname.rstrip(b' \t\r\n\0')
		brand = resp[0x41:0x48]
		brand = brand.rstrip(b' \t\r\n\0')
		version = resp[0x7b:0x7f]
		converted_ip = str(ip[0]) + '.' + \
					str(ip[1]) + '.' + \
					str(ip[2]) + '.' + \
					str(ip[3])
		converted_version = str(version[0]) + '.' + \
					str(version[1]) + '.' + \
					str(version[2]) + '.' + \
					str(version[3])

		print(converted_ip)
		print(str(hostname, 'utf-8'))
		print(str(brand, 'utf-8'))
		print(converted_version)

sock.close()
