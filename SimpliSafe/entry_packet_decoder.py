import crcmod
from Crypto.Cipher import AES
import binascii

def lsfr(buf, feedback):
  new_buf = ''
  buf_len = len(buf)

  if((ord(buf[buf_len - 1]) & 0x01) == 1):
    feedback = True

  for i in range(buf_len - 1, -1, -1):

    tmp = ord(buf[i]) >> 1
    if(i>0):
      if((ord(buf[i-1]) & 0x01) == 1):
        tmp = tmp | 0x80
    new_buf = chr(tmp) + new_buf

    # hardcoded feedback
  if(feedback):
      new_buf = chr(0xE1^ord(new_buf[0])) + new_buf[1:]

  feedback = False
  if((ord(new_buf[buf_len - 1]) & 0x01) == 1):
    feedback = True

  return (new_buf, feedback)

def xor_buffers(buf1, buf2, l=16):
    new_buf = ''
    for i in range(0, 16):
        if(i < l):
          new_buf += chr(ord(buf1[i]) ^ ord(buf2[i]))
        else:
          new_buf += chr(ord(buf1[i]) ^ 0x00)
    return new_buf

def lsfr_xor(data_buf, xor_buf, start_buf, is_debug=False):
  a = start_buf
  check_bit = 0x80
  key_index_byte = 0

  feedback = False
  for i in range(0, 128):

    do_xor = check_bit & ord(data_buf[key_index_byte])
    if(do_xor):
        if(is_debug):
          print('xor_buffers (bit ' + str(i) + ') : ')
          print('  ' + binascii.hexlify(xor_buf))
          print('  ' + binascii.hexlify(a))
        xor_buf = xor_buffers(xor_buf, a)
        if(is_debug):
          print('  res: ' + binascii.hexlify(xor_buf))
          print('')

    if(check_bit == 1):
      check_bit = 0x80
      key_index_byte += 1
    else:
      check_bit = check_bit >> 1

    (a, feedback) = lsfr(a, feedback)
    if(is_debug):
      print("a: " + binascii.hexlify(a))
  return xor_buf

def calc_checksum(pkt):
  var_F5 = 0xFF
  var_F6 = 0xFF
  w = ord(pkt[0]) + 1
  var_F1 = w
  var_F3 = 0
  while True:
    w = (var_F3 - var_F1) & 0xFF
    if(w != 0):
      w = ord(pkt[var_F3])
      var_F2 = w
      var_F4 = 0
      while True:
        var_F0 = 1
        if((0x80 & var_F2) == 0):
          var_F0 = 0
        w = 1
        if((0x80 & var_F6) == 0):
          w = 0
        w ^= var_F0
        carry = var_F5 & 0x80
        var_F5 = (var_F5 << 1) & 0xFF
        var_F6 = (var_F6 << 1) & 0xFF
        if(carry):
          var_F6 |= 0x01
        if(w != 0):
          var_F5 ^= 5
          var_F6 ^= 0x80
        var_F2 = (var_F2 << 1) & 0xFF
        var_F4 += 1
        w = (var_F4 - 8) & 0xFF
        if(w != 0):
            continue
        var_F3 += 1
        break
    else:
        return chr(var_F6) + chr(var_F5)

# test vectors
pkt = '\x16\x02\x00\x72\x89\xcb\xfa\xd2\x02\x7d\x44\x1c\x34\x96\x98\xab\x93\x8e\xe9\x73\xc0\xcd\x9f\x09\x8d'
# this one I got from my entry sensor firmware dump
encr_keys = { '\x00\x72\x89\xcb': '\x35\x3A\xF9\x4B\xFB\xEF\xB9\x80\x8F\xFF\x0A\xD5\x69\x29\x56\xE4'}

import struct

def process_packet(pkt, encr_keys):
    crc16_func = crcmod.mkCrcFun(0x18005, rev=False, initCrc=0xFFFF)
   # crc16_func = crcmod.predefined.mkCrcFun('modbus')
    serial = pkt[2:6]

    key = None
    if(serial in encr_keys):
      key = encr_keys[serial]
      cipher = AES.new(key, AES.MODE_ECB)

    counter = pkt[6:9]
    cmac = pkt[9:13]
    encr_data = pkt[13:23]
    chk_sum = pkt[-2:]
    pkt_len = ord(pkt[0])

    print("=== PACKET DISSECTION ===")
    print("Packet         : " + binascii.hexlify(pkt))
    print("Length         : " + binascii.hexlify(pkt[0]) + " (" + str(pkt_len) + ")")
    print("Serial         :     " + binascii.hexlify(serial))
    print("Counter        :             " + binascii.hexlify(counter))
    print("CMAC:          :                   " + binascii.hexlify(cmac))
    print("Encrypted Data :                           " + binascii.hexlify(encr_data))
    print("Chksum         : "+ " "*((pkt_len+1)*2) + binascii.hexlify(chk_sum))
    print("")

    if(key != None):
      to_encr = serial+counter+'\x00\x00\x00\x00\x00\x00\x00\x00\x02'
      encrypted_buf1 = cipher.encrypt(to_encr)
      decrypted_data = xor_buffers(encrypted_buf1, encr_data, 10)
      print("Data Decryption:")
      print("  AES Call 1 Res : " + binascii.hexlify(encrypted_buf1))
      print("  Decrypted Data : " + binascii.hexlify(decrypted_data[:10]))
      print("")

      print("CMAC Verify:")
      xor_buf = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
      encrypted_buf2 = cipher.encrypt(xor_buf)
      print("  AES Call 2 Res : " + binascii.hexlify(encrypted_buf2))
      start_buf = pkt[0:9] + '\x00\x00\x00\x00\x00\x00\x00'
      lsfr_res1 = lsfr_xor(encrypted_buf2, xor_buf, start_buf)
      print("  LSFR Res1: " + binascii.hexlify(lsfr_res1))
      to_encr = serial+counter+'\x00\x00\x00\x00\x00\x00\x00\x00\x01'
      chk_data1 = xor_buffers(decrypted_data, encrypted_buf1, 10)
      chk_data2 = xor_buffers(lsfr_res1, chk_data1, 10)
      print("  CHK Data1 : " + binascii.hexlify(chk_data1[0:10]))
      print("  CHK Data2 : " + binascii.hexlify(chk_data2))
      lsfr_res2 = lsfr_xor(encrypted_buf2, xor_buf, chk_data2)
      print("  LSFR Res2: " + binascii.hexlify(lsfr_res2))
      lsfr_res2_xor = xor_buffers(lsfr_res2, '\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x50')
      print("  LSFR Res2_xor: " + binascii.hexlify(lsfr_res2_xor))
      lsfr_res3 = lsfr_xor(encrypted_buf2, xor_buf, lsfr_res2_xor)
      print("  LSFR Res3: " + binascii.hexlify(lsfr_res3))
      encrypted_buf3 = cipher.encrypt(to_encr)
      print("  AES Call 3 Res : " + binascii.hexlify(encrypted_buf3))
      chk_data3 = xor_buffers(lsfr_res3, encrypted_buf3)
      print("  CHK Data3 (CALCULATED CMAC): " + binascii.hexlify(chk_data3[0:4]))
      if(chk_data3[0:4] == cmac):
        print("    \033[92m CMAC Match!\033[00m")
      else:
        print("    \033[91m CMAC Mismatch!\033[00m")
    else:
        print("No key found to decrypt or verify CMAC")

    print("")
    print("Checksum Verify:")
    calc_chk_sum = calc_checksum(pkt[0:pkt_len + 1])
    print("test: " + hex(crc16_func(pkt[0:pkt_len + 1])))

    print("  Calculated Checksum:" + binascii.hexlify(calc_chk_sum))

    if(calc_chk_sum == chk_sum):
      print("    \033[92m Checksum Verified!\033[00m")
    else:
      print("    \033[91m Bad Checksum!\033[00m")
