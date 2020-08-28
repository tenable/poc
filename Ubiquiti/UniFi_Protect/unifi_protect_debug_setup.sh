#!/bin/bash

# Enable console
setting='{
  "logs": {
    "enableConsole": true
  }
}'
file="/etc/unifi-protect/config.json"

echo

if [ ! -e "$file" ]; then
  echo "$setting" > "$file"
  echo "Created custom override config.json  : /etc/unifi-protect/config.json"
elif ! grep '"enableConsole": true' "$file" > /dev/null; then
  echo "/etc/unifi-protect/config.json exists, add setting manually:"
  echo "$setting"
else
  echo "Verified custom override config.json : /etc/unifi-protect/config.json"
fi

# Create a debug version of startup script config file
cp /etc/default/unifi-protect /etc/default/unifi-protect.debug
echo -e "NODE_DEBUG=TRUE" >> /etc/default/unifi-protect.debug

# Create a debug version of the startup script
cp /usr/bin/unifi-protect /usr/bin/unifi-protect.debug
sed -i 's|/etc/default/unifi-protect|/etc/default/unifi-protect.debug|' /usr/bin/unifi-protect.debug
sed -i 's/node/node --inspect=0.0.0.0 --inspect-brk/' /usr/bin/unifi-protect.debug

echo "Created debugging config file        : /etc/default/unifi-protect.debug"
echo "Created debugging startup script     : /usr/bin/unifi-protect.debug"
echo
echo "To run unifi-protect with debugging, run : "
echo "  service unifi-protect stop && /usr/bin/unifi-protect.debug"
echo
echo "When finished, use CTRL+C to abort the process and then start the service again :"
echo "  service unifi-protect start"
echo
