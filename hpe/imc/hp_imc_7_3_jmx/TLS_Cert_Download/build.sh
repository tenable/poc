source ../vars.txt
mkdir classes

# compile
javac -d classes src/local/rmi/*.java src/tls/cert/*.java

# build JAR
cd classes
jar -cvfe ../DownloadCert.jar tls.cert.Runner local/rmi/*.class tls/cert/*.class
