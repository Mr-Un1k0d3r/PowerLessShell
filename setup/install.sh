#!/bin/bash
if [ "$EUID" -ne 0 ] 
then
	echo "Installer need to be run as root"
	exit
fi
apt update
apt install git python-crypto python-pyasn1 -y
git clone https://github.com/CoreSecurity/impacket
cd impacket
python setup.py install

