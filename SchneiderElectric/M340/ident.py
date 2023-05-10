## Requires PyModbus
## Identifies M340 Controllers

import sys
import struct
# --------------------------------------------------------------------------- #
# import the various server implementations
# --------------------------------------------------------------------------- #
from pymodbus.pdu import ModbusRequest, ModbusResponse, ModbusExceptions
from pymodbus.client.sync import ModbusTcpClient as ModbusClient
from pymodbus.bit_read_message import ReadCoilsRequest
from pymodbus.compat import int2byte, byte2int
# --------------------------------------------------------------------------- #
# configure the client logging
# --------------------------------------------------------------------------- #
import logging
logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.DEBUG)

umas_fn = 0

def UMAS_READ_ID(data):
    i = 0
    values = []
    # response code
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # PLC family
    values.append(struct.unpack('>B', data[i:i + 1])[0])
    i += 1
    # PLC Type
    values.append(struct.unpack('>B', data[i:i + 1])[0])
    i += 1
    # PLC ID
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # PLC Model
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # unknown
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # firmware version
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # patch version
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # Ir
    values.append(struct.unpack('>H', data[i:i + 2])[0])
    i += 2
    # HwId
    values.append(struct.unpack('>I', data[i:i + 4])[0])
    i += 4
    # FwLoc
    values.append(struct.unpack('>I', data[i:i + 4])[0])
    i += 4
    # Device Name Len
    dname_len = struct.unpack('>B', data[i:i + 1])[0]
    values.append(dname_len)
    i += 1
    # Device Name
    values.append(struct.unpack(str(dname_len) + 's', data[i:i + dname_len])[0])
    return values

class UMASModbusResponse(ModbusResponse):
    function_code = 90
    _rtu_byte_count_pos = 2

    def __init__(self, values=None, address=None, **kwargs):
        ModbusResponse.__init__(self, **kwargs)
        self.values = values or []

    def encode(self):
        """ Encodes response pdu
        :returns: The encoded packet message
        """
        result = int2byte(len(self.values) * 2)
        for register in self.values:
            result += struct.pack('>H', register)
        return result

    def decode(self, data):
        """ Decodes response pdu
        :param data: The packet data to decode
        """
        self.values = []
        import binascii
        print("Data: %s" % binascii.hexlify(data))

        global umas_fn
        # system info
        if(umas_fn == 2):
          self.values = UMAS_READ_ID(data)
        elif(umas_fn == 0x20):
            pass

        return

class UMASModbusRequest(ModbusRequest):
    function_code = 90
    _rtu_frame_size = 8

    def __init__(self, address=None, header='', **kwargs):
        ModbusRequest.__init__(self, **kwargs)
        self.address = address
        self.header = header
        global umas_fn
        umas_fn = address
    def encode(self):
        return struct.pack('>H', self.address) + self.header

    def decode(self, data):
        self.address = struct.unpack('>H', data)

    def execute(self, context):
        if not (1 <= self.count <= 0x7d0):
            return self.doException(ModbusExceptions.IllegalValue)
        if not context.validate(self.function_code, self.address, self.count):
            return self.doException(ModbusExceptions.IllegalAddress)
        values = context.getValues(self.function_code, self.address)
        return UMASModbusResponse(values=values)

if __name__ == "__main__":

    if(len(sys.argv) < 2):
        print("Usage: python3 ident.py <host> <optional_port>")
        exit()

    if(len(sys.argv) < 3):
        port = 502
    else:
        port = int(sys.argv[2])

    host = sys.argv[1]

    with ModbusClient(host=host, port=port) as client:
        client.register(UMASModbusResponse)

        print("Sending READ_ID...")
        request = UMASModbusRequest(2, unit=0)
        result = client.execute(request)
        values = result.values

        response_code = values[0]
        print("Response:")
        print("")
        if(response_code == 0xFE):
            print("Response Code: OK")
        elif(response_code == 0xFD):
            print("Response Code: ERROR")
        else:
            print("Response Code: UKNOWN")

        print("PLC Family       : %d" % values[1])
        print("PLC Type         : %d" % values[2])
        print("PLC ID           : %d" % values[3])
        print("PLC Model        : %d" % values[4])
        print("Unknown          : %d" % values[5])
        print("Firmware Version : %d.%d" % ((values[6]&0x0F), (values[6]%0xF0)/0x10))
        print("Patch Version    : %d" % values[7])
        print("Ir               : %d" % values[8])
        print("HWID             : %d" % values[9])
        print("FWLOC            : %d" % values[10])
        print("Device Name Len  : %d" % values[11])
        print("Device Name      : %s" % values[12])


        request = UMASModbusRequest(0x20, unit=0, header='\x01\x14\x00\x00\x00\x00\x00\x00\x02')
        result = client.execute(request)
        values = result.values
