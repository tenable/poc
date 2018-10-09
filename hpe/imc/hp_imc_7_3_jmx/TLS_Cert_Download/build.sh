JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.7.0_76.jdk/Contents/Home
mkdir classes

# compile
$JAVA_HOME/bin/javac -d classes src/local/rmi/*.java src/tls/cert/*.java

# build JAR
cd classes
$JAVA_HOME/bin/jar -cvfe ../DownloadCert.jar tls.cert.Runner local/rmi/*.class tls/cert/*.class
