source ../vars.txt
mkdir classes
javac -d ./classes src/mbean/cmd/*.java
cd classes
jar -cvf ../ExecCommand.jar .
