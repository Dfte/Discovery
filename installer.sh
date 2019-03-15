#!/bin/bash
###################
# Python3 librairy
###################
pip3 install shodan python-nmap beautifulsoup4 validators mysql-connector-python
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
git clone	git://git.kali.org/packages/bing-ip2hosts.git
cd bing-ip2hosts 
chmod u+x bing-ip2hosts
mv bing-ip2hosts /usr/bin
cd ../
rm -R bing-ip2hosts
