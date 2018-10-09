source ../vars.txt
mkdir classes

# compile
javac -d classes src/jmx_rmi_client/*.java

# build JAR
cd classes
jar -cvfe ../RunExploit.jar jmx_rmi_client.Client jmx_rmi_client/*.class
