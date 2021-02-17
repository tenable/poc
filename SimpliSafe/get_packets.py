from rflib import *
import binascii
from packet_decoder import *

encr_keys = { '\x00\x72\x89\xcb': '\x35\x3A\xF9\x4B\xFB\xEF\xB9\x80\x8F\xFF\x0A\xD5\x69\x29\x56\xE4'}

d = RfCat()

d.setFreq(433899963)
d.setMdmModulation(MOD_2FSK)
d.setMdmSyncWord(0x930b)
d.setMdmSyncMode(SYNCM_16_of_16)
d.setMdmSyncMode(SYNCM_CARRIER_16_of_16)
d.setMdmDRate(4800)
d.makePktFLEN(0xff)

print("Press <enter> to stop")

while not keystop():
  try:
    pkt,t = d.RFrecv()
    pkt = pkt[2:]
    length = ord(pkt[0])

    pkt = pkt[:length+3]
    print("***********************************************************************")
    print("Packet Recieved: ")
    print(binascii.hexlify(pkt))
    process_packet(pkt, encr_keys)
    print("***********************************************************************")
  except ChipconUsbTimeoutException:
    pass
  except KeyboardInterrupt:
    print("Please press <enter> to stop")
