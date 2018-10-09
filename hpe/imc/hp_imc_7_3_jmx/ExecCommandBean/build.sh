JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.7.0_76.jdk/Contents/Home
mkdir classes
$JAVA_HOME/bin/javac -d ./classes src/mbean/cmd/*.java
cd classes
$JAVA_HOME/bin/jar -cvf ../ExecCommand.jar .
