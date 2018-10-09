ip=192.168.1.194
dir=`pwd`

# Note: you will need to drop "deploy.jar" in this directory

# compile
javac -cp "$dir/deploy.jar" -d classes Runit.java

# run it
java -cp "$dir/deploy.jar:$dir/classes" Runit $ip
