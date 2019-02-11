# Discovery

Discovery is a fully automated OSINT tool that will gather informations from a lot of differents sources. Actually this is the beta test version :) !

Discovery relies on 6 modules that can be used all at once or independently. All you need to have to launch the tool is a domain name.

## Warning

This tool relies on 4 FREE API's : 
- Shodan : https://www.shodan.io/
- WhatCMS : https://whatcms.org/API
- Hunter.io : https://hunter.io/
- RocketReach : https://rocketreach.co/api 

Most of the functions won't work without API keys.

## Whois/DNS request

This module can be called this way :

    python3 discovery.py -d "domain_name" --dns

First of all it will query whois databases to gather informations about the domain name (who registered it, who is responsible of it etc...)

Then it will query Google DNS (8.8.8.8) to retrieve records. As for now it will also try to perform a DNS zone transfert and tell you if it went ok or not :

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/1.png">
</p>

## DNS enumeration

The second module is the implementaiton of the sublist3r python3 module written by aboulela :
https://github.com/aboul3la/Sublist3r
You can call it using two differents options :

    python3 discovery.py -d "domain_name" --sublist
or

    python3 discovery.py -d "domain_name" --subrute

The difference is that when using --subrute, sublist3r will perform a DNS bruteforce which will take much more time but will also find more subdomains.
<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/2.png">
</p>

## Scanner module

This module is composed of two functions and can be called that way :

    python3 discovery.py -d "domain_name" --scan ["full" or "fast"]

The first function is an implementaiton of the python nmap librairy. It will scan the discovered IP's either the "full" way (which means it will check for the all 65535 ports) or the "fast" way (-F nmap option).

Depending of the services discovered it will perform a few actions. Actually I only took care of the HTTP/HTTPS services. So the script will check the SSL certificate, check for the CMS used (if there is one), check for comon important files (.git, /status, trace.axd, robots.txt).

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/6.png">
</p>

>Note : you can add as much files as you want in the "warning_file" file in the configuration directory.

It will also look for potential WAF using the wafwoof tool developped by EnableSecurity : https://github.com/EnableSecurity/wafw00f

The second function will use the Shodan API to gather informations about the domain name : found servers, services, CVE's related to the services and so on...
<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/5.png">
</p>

## Metadatas Scrapper

This module is basically my Linux version of FOCA :

    python3 discovery.py -d "domain_name" --gather "number_of_pages_to_crawl"

Using Google dorks it will gather publicly exposed documents and parse their metadatas in order to find sensitive informations (credentials for exemple)
This module is inspired by the pyfoca script written by altjx : https://github.com/altjx/ipwn/tree/master/pyfoca

To parse the metadatas I used exiftool.

>Note : you can add as much extensions as you want in the "extensions" file in the configuration directory
<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/3.png">
</p>

## Harvestor

The last module will use differents API's to gather names of employee working for the given domain name. It will then create a few lists of emails for each emails patterns implemented (currently 4) :

    python3 discovery.py -d "domain_name" --harvest 

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/4.png">
</p>

# Full command 

So basically if you want to run all modules you can use this command :

    python3 discovery.py -d "domain_name" --dns (--sublist or --subrute) --scan (full or fast) --gather x -- harvest
All results will be written in a file in this tree :

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/7.png">
</p>

# To Do list :
 - Review try/except blocks
 - Add a quick description for each CVE detected by Shodan
 - Query HaveIBeenPowned API to gather statistics about pwned emails 
 - May be add some web scanner or API that detects flaws related to a certain CMS  
 - Improve the scanning function for different services
 - Find a way to deal with Googles Captchas
 - Dynamic display for the document dowloads
 - Bug in the scanning function (warning files detected whereas they souldn't)
 - add ip2host to detect new virtual hosts
 - check for reverse dns 
 - Check CN's in protocoles' certificates (ssh, ftps....)
 - Improve scanning phase
 - Add Http screenshot
 - Add searhcsploit


