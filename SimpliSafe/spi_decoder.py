command_strobes = {
  0x30 : ['SRES','Reset chip'],
  0x31 : ['SFSTXON','Enable and calibrate frequency synthesizer (if SETTLING_CFG.FS_AUTOCAL = 1).'],
  0x32 : ['SXOFF','Enter XOFF state when CSn is de-asserted'],
  0x33 : ['SCAL','Calibrate frequency synthesizer and turn it off.'],
  0x34 : ['SRX','Enable RX'],
  0x35 : ['STX','In IDLE state: Enable TX'],
  0x36 : ['SIDLE','Exit RX/TX, turn off frequency synthesizer and exit eWOR mode if applicable'],
  0x37 : ['SAFC','Automatic Frequency Compensation'],
  0x38 : ['SWOR','Start automatic RX polling sequence (eWOR) as described in Section 9.6 if WOR_CFG0.RC_PD = 0'],
  0x39 : ['SPWD','Enter SLEEP mode when CSn is de-asserted'],
  0x3a : ['SFRX','Flush the RX FIFO.'],
  0x3b : ['SFTX','Flush the TX FIFO'],
  0x3c : ['SWORRST','Reset the eWOR timer to the Event1 value'],
  0x3d : ['SNOP','No operation. May be used to get access to the chip status byte']
}

regular_registers = {
0x00 : ["IOCFG3", "GPIO3 Pin Configuration"],
0x01 : ["IOCFG2", "GPIO2 Pin Configuration"],
0x02 : ["IOCFG1", "GPIO1 Pin Configuration"],
0x03 : ["IOCFG0", "GPIO0 Pin Configuration"],
0x04 : ["SYNC3", "Sync Word Configuration [31:23]"],
0x05: ["SYNC2", "- Sync Word Configuration [23:16]"],
0x06: ["SYNC1", "Sync Word Configuration [15:8]"],
0x07: ["SYNC0", "Sync Word Configuration [7:0]"],
0x08: ["SYNC_CFG1", "Sync Word Detection Configuration Reg. 1"],
0x09: ["SYNC_CFG0", "Sync Word Length Configuration Reg. 0"],
0x0A: ["DEVIATION_M", "- Frequency Deviation Configuration"],
0x0B: ["MODCFG_DEV_E", "Modulation Format and Frequency Deviation Configuration"],
0x0C: ["DCFILT_CFG", "Digital DC Removal Configuration"],
0x0D: ["PREAMBLE_CFG1", "Preamble Length Configuration Reg. 1"],
0x0E: ["PREAMBLE_CFG0", "Preamble Length Configuration Reg. 0"],
0x0F: ["FREQ_IF_CFG", "RX Mixer Frequency Configuration"],
0x10: ["IQIC", "Digital Image Channel Compensation Configuration"],
0x11: ["CHAN_BW", "Channel Filter Configuration"],
0x12: ["MDMCFG1", "General Modem Parameter Configuration Reg. 1"],
0x13: ["MDMCFG0", "General Modem Parameter Configuration Reg. 0"],
0x14: ["SYMBOL_RATE2", "- Symbol Rate Configuration Exponent and Mantissa [19:16]"],
0x15: ["SYMBOL_RATE1", "Symbol Rate Configuration Mantissa [15:8]"],
0x16: ["SYMBOL_RATE0", "Symbol Rate Configuration Mantissa [7:0]"],
0x17: ["AGC_REF", "AGC Reference Level Configuration"],
0x18: ["AGC_CS_THR", "Carrier Sense Threshold Configuration"],
0x19: ["AGC_GAIN_ADJUST", "RSSI Offset Configuration"],
0x1A: ["AGC_CFG3", "Automatic Gain Control Configuration Reg. 3"],
0x1B: ["AGC_CFG2", "Automatic Gain Control Configuration Reg. 2"],
0x1C: ["AGC_CFG1", "Automatic Gain Control Configuration Reg. 1"],
0x1D: ["AGC_CFG0", "Automatic Gain Control Configuration Reg. 0"],
0x1E: ["FIFO_CFG", "FIFO Configuration"],
0x1F: ["DEV_ADDR", "Device Address Configuration"],
0x20: ["SETTLING_CFG", "Frequency Synthesizer Calibration and Settling Configuration"],
0x21: ["FS_CFG", "Frequency Synthesizer Configuration"],
0x22: ["WOR_CFG1", "- eWOR Configuration Reg. 1"],
0x23: ["WOR_CFG0", "- eWOR Configuration Reg. 0"],
0x24: ["WOR_EVENT0_MSB", "Event 0 Configuration MSB"],
0x25: ["WOR_EVENT0_LSB", "Event 0 Configuration LSB"],
0x26: ["PKT_CFG2", "Packet Configuration Reg. 2"],
0x27: ["PKT_CFG1", "Packet Configuration Reg. 1"],
0x28: ["PKT_CFG0", "Packet Configuration Reg. 0"],
0x29: ["RFEND_CFG1", "RFEND Configuration Reg. 1"],
0x2A: ["RFEND_CFG0", "RFEND Configuration Reg. 0"],
0x2B: ["PA_CFG2", "Power Amplifier Configuration Reg. 2"],
0x2C: ["PA_CFG1", "Power Amplifier Configuration Reg. 1"],
0x2D: ["PA_CFG0", "Power Amplifier Configuration Reg. 0"],
0x2E: ["PKT_LEN", "Packet Length Configuration"]
}

extended_registers =  {
0x00: ["IF_MIX_CFG", "IF Mix Configuration"],
0x01: ["FREQOFF_CFG", "Frequency Offset Configuration"],
0x02: ["TOC_CFG", "Timing Offset Correction Configuration"],
0x03: ["MARC_SPARE", "MARC Spare"],
0x04: ["ECG_CFG", "External Clock Frequency Configuration"],
0x05: ["CFM_DATA_CFG", "Custom Frequency Modulation Configuration"],
0x06: ["EXT_CTRL", "External Control Configuration"],
0x07: ["RCCAL_FINE", "RC Oscillator Calibration Fine"],
0x08: ["RCCAL_COARSE", "RC Oscillator Calibration Coarse"],
0x09: ["RCCAL_OFFSET", "RC Oscillator Calibration Clock Offset"],
0x0A: ["FREQOFF1","Frequency Offset MSB"],
0x0B: ["FREQOFF0","Frequency Offset LSB"],
0x0C: ["FREQ2","Frequency Configuration"],
0x0D: ["FREQ1","Frequency Configuration"],
0x0E: ["FREQ0","Frequency Configuration"],
0x0F: ["IF_ADC2", "Analog to Digital Converter Configuration Reg. 2"],
0x10: ["IF_ADC1", "Analog to Digital Converter Configuration Reg. 1"],
0x11: ["IF_ADC0", "Analog to Digital Converter Configuration Reg. 0"],
0x12: ["FS_DIG1","Frequency Synthesizer Digital Reg. 1"],
0x13: ["FS_DIG0","Frequency Synthesizer Digital Reg. 0"],
0x14: ["FS_CAL3","Frequency Synthesizer Calibration Reg. 3"],
0x15: ["FS_CAL2","Frequency Synthesizer Calibration Reg. 2"],
0x16: ["FS_CAL1","Frequency Synthesizer Calibration Reg. 1"],
0x17: ["FS_CAL0","Frequency Synthesizer Calibration Reg. 0"],
0x18: ["FS_CHP","Frequency Synthesizer Charge Pump Configuration"],
0x19: ["FS_DIVTWO","Frequency Synthesizer Divide by 2"],
0x1A: ["FS_DSM1", "FS Digital Synthesizer Module Configuration Reg. 1"],
0x1B: ["FS_DSM0","FS Digital Synthesizer Module Configuration Reg. 0"],
0x1C: ["FS_DVC1","Frequency Synthesizer Divider Chain Configuration .."],
0x1D: ["FS_DVC0","Frequency Synthesizer Divider Chain Configuration .."],
0x1E: ["FS_LBI", "Frequency Syntesizer Local Bias Configuration"],
0x1F: ["FS_PFD","Frequency Synthesizer Phase Frequency Detector Con.."],
0x20: ["FS_PRE","Frequency Synthesizer Prescaler Configuration"],
0x21: ["FS_REG_DIV_CML","Frequency Synthesizer Divider Regulator Configurat.."],
0x22: ["FS_SPARE","Frequency Synthesizer Spare"],
0x23: ["FS_VCO4","FS Voltage Controlled Oscillator Configuration Reg.."],
0x24: ["FS_VCO3","FS Voltage Controlled Oscillator Configuration Reg.."],
0x25: ["FS_VCO2","FS Voltage Controlled Oscillator Configuration Reg.."],
0x26: ["FS_VCO1","FS Voltage Controlled Oscillator Configuration Reg.."],
0x27: ["FS_VCO0","FS Voltage Controlled Oscillator Configuration Reg.."],
0x28: ["GBIAS6", ""],
0x29: ["GBIAS5", ""],
0x2a: ["GBIAS4", ""],
0x2b: ["GBIAS3", ""],
0x2c: ["GBIAS2", ""],
0x2d: ["GBIAS1", ""],
0x2e: ["GBIAS0", ""],
0x2f: ["IFAMP", ""],
0x30: ["LNA", ""],
0x31: ["RXMIX", ""],
0x32: ["XOSC5","Crystal Oscillator Configuration Reg. 5"],
0x33: ["XOSC4","Crystal Oscillator Configuration Reg. 4"],
0x34: ["XOSC3","Crystal Oscillator Configuration Reg. 3"],
0x35: ["XOSC2","Crystal Oscillator Configuration Reg. 2"],
0x36: ["XOSC1","Crystal Oscillator Configuration Reg. 1"],
0x91: ["SERIAL_STATUS","Serial Status"]
}

# to hold register values
regular_register_values = dict()
extended_register_values = dict()

fifo_record = []

# initialize
for key in regular_registers.keys():
    regular_register_values[key] = list()

for key in extended_registers.keys():
    extended_register_values[key] = list()

import sys

fh = open(sys.argv[1])
lines = fh.readlines()
import re
import texttable as tt

cur_packet_id = -1
burst_mode = 0
address = 0
extended_register = 0
standard_fifo_start = 0

write = False
destination_register = 0
fifo_content = ''

for line in lines:
  if(line[0] == "T"):
    continue

  if(line.split(',')[1] == ''):
      continue

  packet_id = int(line.split(',')[1])

  # read packet header
  if(packet_id != cur_packet_id):
    if(fifo_content != ''):
      fifo_record.append(fifo_content)
      print('fifo content: ' + fifo_content)

    fifo_content = ''
    extended_register = 0
    standard_fifo_start = 0

    print("")
    print("Header for packet ID: " + str(packet_id))
    cur_packet_id = packet_id
    m = re.search("\((0x[a-fA-F0-9]{2})\)", line.split(',')[2])
    header_byte = m.group(1)
    header_byte = int(m.group(1),16)
    print("Header Byte: " + "0x{:02x}".format(header_byte))

    # read / write
    if(header_byte & 0x80):
      print("Access type: Read")
      write = False
    else:
      print("Access type: Write")
      write = True

    # burst access
    if(header_byte & 0x40):
      print("Burst Access: True")
      burst_mode = 1
    else:
      print("Burst Access: False")
      burst_mode = 0

    # address
    address = (header_byte & 0x3f)

    print('Address: ' + "0x{:02x}".format(address))
    if(address == 0x2f):
      print("  Extended Register")
    elif((header_byte & 0x3f) < 0x30):
      print("  Regular Register " + regular_registers[address][0])
      destination_register = address
    elif(address == 0x3e):
      print("  Direct FIFO Access")
    elif(address == 0x3f):
      print("  Standard FIFO Access")
      standard_fifo_start = 1
    else:
      print("  Command Strobe - " + command_strobes[address][0] + ' - ' + command_strobes[address][1])
  else:
    m = re.search("\((0x[a-fA-F0-9]{2})\)", line.split(',')[2])
    data_byte = m.group(1)
    data_byte = int(m.group(1),16)

    m = re.search("\((0x[a-fA-F0-9]{2})\)", line.split(',')[3])
    data_byte_read = m.group(1)
    data_byte_read = int(m.group(1),16)

    if(address == 0x2f): # extended register access
        address = data_byte & 0x3f
        extended_register = 1
        continue

    if(standard_fifo_start):
      if(write):
        if(fifo_content == ''):
            fifo_content += '<op - write> : '
        fifo_content += "{:02x}".format(data_byte)
      else:
        if(fifo_content == ''):
            fifo_content += '<op - read>  : '
        fifo_content += "{:02x}".format(data_byte_read)

    if(extended_register):
        if(write):
          print("    byte written (" + "0x{:02x}".format(address) + "[" + extended_registers[address][0] + "]) - " + "0x{:02x}".format(data_byte))
          extended_register_values[address].append(hex(data_byte))
        else:
          print("    byte read    (" + "0x{:02x}".format(address) + "[" + extended_registers[address][0] + "]) - " + "0x{:02x}".format(data_byte_read))
    else:
        if(write):
          regular_register_values[destination_register].append("0x{:02x}".format(data_byte))
          print("    byte written (" + "0x{:02x}".format(address) + ") - " + "0x{:02x}".format(data_byte))
        else:
          print("    byte read (" + "0x{:02x}".format(address) + ") - " + "0x{:02x}".format(data_byte_read))

    address += 1

# output register values in a table
def dump_register_values(register_name_dict, register_value_dict):
    tab = tt.Texttable()
    headings = ['Address', 'Name', 'Hex Value', 'Decimal', 'Binary']
    tab.header(headings)
    for address in register_value_dict.keys():

        if register_value_dict[address] == '':
            dec_val = bin_val = ''  # empty
        else:
            dec_val = map(lambda x: int(x, 16), register_value_dict[address]) #int(register_value_dict[address], 16)
            #dec_val = register_value_dict[address]#str(int_val)
            bin_val = map(lambda x: bin(x).replace('0b',''), dec_val) #register_value_dict[address]#bin(int_val).replace('0b','')

        tab.add_row(
            [   
                "0x{:02x}".format(address),
                register_name_dict[address][0], # name
                register_value_dict[address],   # hex
                dec_val,                        # decimal
                bin_val                         # binary
            ]   
        )   

    print(tab.draw())

print("\nRegular registers:\n")
dump_register_values(regular_registers, regular_register_values)
print("\nExtended registers:\n")
dump_register_values(extended_registers, extended_register_values)

print("\nFifo Dump (read + write):\n")
for record in fifo_record:
  print(record)
