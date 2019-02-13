#!/bin/bash
###################
# Python3 librairy
###################
pip3 install shodan python-nmap beautifulsoup4 validators
git clone https://github.com/rthalley/dnspython.git
cd dnspython
python3 setup.py install
cd ../
git clone https://github.com/joepie91/python-whois.git
cd python-whois
python3 setup.py install
cd ../


#################
# Required tools
#################
apt -y install sublist3r dnsutils extract wafw00f exiftool
