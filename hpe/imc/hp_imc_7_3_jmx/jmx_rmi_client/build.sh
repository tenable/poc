JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.7.0_76.jdk/Contents/Home
mkdir classes

# compile
$JAVA_HOME/bin/javac -d classes src/jmx_rmi_client/*.java

# build JAR
cd classes
$JAVA_HOME/bin/jar -cvfe ../RunExploit.jar jmx_rmi_client.Client jmx_rmi_client/*.class
