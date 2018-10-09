# build malicious bean
echo
echo '[+] Building MBean...'
cd ExecCommandBean
./build.sh
cd ..

# build RMI dumper
echo
echo '[+] Building RMI Dumper...'
cd rmi-dumpregistry
./build.sh
cd ..

# build TLS certificate downloader
echo
echo '[+] Building TLS cert downloader...'
cd TLS_Cert_Download
./build.sh
cd ..

# build RCE exploit client
echo
echo '[+]Building RCE exploit client...'
cd jmx_rmi_client
./build.sh
cd ..

# copy all JARS to current directory
echo
echo '[+] Copying JARS to current dir...'
cp ExecCommandBean/ExecCommand.jar .
cp TLS_Cert_Download/DownloadCert.jar .
cp jmx_rmi_client/RunExploit.jar .

echo && echo
echo 'Ready to launch run.sh. Ensure script is configured properly.'
echo
