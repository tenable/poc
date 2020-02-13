from bluepy.btle import *
import argparse

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            print "Discovered device", dev.addr, " ", str(dev.getScanData())

desc = 'SimpliSafe Wi-Fi Config Changer (over BTLE)'
arg_parser = argparse.ArgumentParser(description=desc)
arg_parser.add_argument('--ssid', required=True, help='Wi-Fi Network Name (SSID)')
arg_parser.add_argument('--password', required=True, help='Wi-Fi Network Password')
arg_parser.add_argument('--token', default='test', help='Token')
args = arg_parser.parse_args()

# Wi-Fi credentials to write
ssid = args.ssid
password = args.password
token = args.token

scanner = Scanner().withDelegate(ScanDelegate())
devices = scanner.scan(10.0)
simplisafe = None

for dev in devices:
    print "Device %s (%s), RSSI=%d dB, connectable=%s, " % (dev.addr, dev.addrType, dev.rssi, dev.connectable)
    local_name = dev.getValueText(0x9)
    if local_name is not None and "SimpliSafe" in local_name:
        simplisafe = dev
        print "\nFound '" + local_name + "'"
        break
    
print ""

if simplisafe is None:
    print "Did not find SimpliSafe device."
else:
    try:
        print "Getting peripheral"
        device = Peripheral(simplisafe.addr, simplisafe.addrType)
    except BTLEException, e:
        print "Error connecting to device."
    svc_uuid = "000000ff-0000-1000-8000-00805f9b34fb"
    print "Getting service..."
    svc = device.getServiceByUUID(svc_uuid)

    char_uuid = UUID("0000ff01-0000-1000-8000-00805f9b34fb")
    chars = svc.getCharacteristics(char_uuid)

    if len(chars) > 0:
        print "Found characteristic"
        char = chars[0]

        print "Writing..."
        # e.g. \n{"ssid":"thessid", "pass":"thepass", "token":"thetoken"}\r
        payload = '\n{"ssid":"'+ssid+'", "pass":"'+password+'", "token":"'+token+'"}' + "\r"

        char.write(payload, True)
        if char.supportsRead():
            print "Supports reading"
            print char.read()

    device.disconnect()

print "Done."
