#!/bin/bash

# Create debug version of startup script config file
cp /etc/default/unifi-management-portal /etc/default/unifi-management-portal.debug
sed -i 's/LOG_LEVEL="WARN"/LOG_LEVEL="LOG"/' /etc/default/unifi-management-portal.debug

# Make a debug version of the startup script
cp /usr/bin/unifi-management-portal /usr/bin/unifi-management-portal.debug
sed -i 's|/etc/default/unifi-management-portal|/etc/default/unifi-management-portal.debug|' /usr/bin/unifi-management-portal.debug
sed -i 's/node /node --inspect=0.0.0.0 /' /usr/bin/unifi-management-portal.debug

echo
echo "Created debugging config file    : /etc/default/unifi-management-portal.debug"
echo "Created debugging startup script : /usr/bin/unifi-management-portal.debug"
echo
echo "To run unifi-management-portal with debugging, run : "
echo "  service unifi-management-portal stop && /usr/bin/unifi-management-portal.debug"
echo
echo "When finished, use CTRL+C to abort the process and then start the service again :"
echo "  service unifi-management-portal start"
echo
