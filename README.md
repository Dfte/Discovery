# Discovery

Discovery is a fully automated OSINT tool that will gather informations from a lot of differents sources. 
Discovery relies on 6 modules that can be used all at once or independently. All you need to have to launch the tool is a domain name.

## Warning

This tool relies on 4 FREE API's : 
- Shodan : https://www.shodan.io/
- WhatCMS : https://whatcms.org/API
- Hunter.io : https://hunter.io/
- RocketReach : https://rocketreach.co/api 

BUT !

With Discovery v1.2 you can now use a huge part of the tool even without the API keys. Note that you will not be able to use the harvester module nor the shodan and whatCMS api.

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
<img src="https://github.com/Dfte/Discovery/blob/master/images/12.png">
</p>

## Scanner module

This module is composed of two functions and can be called that way :

    python3 discovery.py -d "domain_name" --scan ["full" or "fast"]

The first function is an implementaiton of the python nmap librairy. It will scan the discovered IP's either the "full" way (which means it will check for the all 65535 ports) or the "fast" way (-F nmap option).

Depending of the services discovered it will perform a few actions. Actually I only took care of the HTTP/HTTPS services. So the script will check the SSL certificate, check for the CMS used (if there is one), check for comon important files (.git, /status, trace.axd, robots.txt. If those files are found, they will be downloaded).

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/16.png">
</p>

>Note : you can add as much files as you want in the "warning_file" file in the configuration directory.

It will also look for potential WAF using the wafwoof tool developped by EnableSecurity : https://github.com/EnableSecurity/wafw00f

The tool will output an XML files that will be used with searchsploit in order to present you some exploits. (I still have to work on parsing the output of searchsploit but hey... This is coming soon :) )

The second function will use the Shodan API to gather informations about the domain name : found servers, services, CVE's related to the services as much as a description of CVE's found :
<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/15.png">
</p>

## Metadatas Scrapper

This module is basically my Linux version of FOCA :

    python3 discovery.py -d "domain_name" --gather

Using Google dorks it will gather publicly exposed documents and parse their metadatas in order to find sensitive informations (credentials for exemple)
This module is inspired by the pyfoca script written by altjx : https://github.com/altjx/ipwn/tree/master/pyfoca

To parse the metadatas I used exiftool.

>Note : you can add as much extensions as you want in the "extensions" file in the configuration directory
<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/13.png">
</p>

All files found will be downloaded and parsed. 

## Harvestor

The last module will use differents API's to gather names of employee working for the given domain name. It will then create a few lists of emails for each emails patterns implemented (currently 4) :

    python3 discovery.py -d "domain_name" --harvest 

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/18.png">
</p>

# Full command 

So basically if you want to run all modules you can use this command :

    python3 discovery.py -d "domain_name" --dns (--sublist or --subrute) --scan (full or fast) --gather --harvest
All results will be written in a file in this tree :

<p align="center">
<img src="https://github.com/Dfte/Discovery/blob/master/images/17.png">
</p>

# To Do list :
 - Code refactoring
    - Use of class
    - each functions/modules in separate files
    - add more configuration options
    - Review of the already existing code (adding some performance)

 - Document gathering :
    - Search for sensitive files on Pastebin/Github (DONE FOR PASTEBIN)
    - Archive.org : error messages
    - Google dorks (index of, error message)
    - Add this API : psbdmp.ws
    
 - Scanning function
    - May be add some web scanner or API that detects flaws related to a certain CMS  
    - Add Http screenshot
    - Searchsploit and parse output of searchsploit results
    - Add UDP scans
    - Dirbuster ? http/s vhost/ipt 
    - If SVN or .git -> dvcs ripper ???
 
 - DNS enumeration 
    - Create list of IP using ripe databsaes results
    - add BING ip2host to detect new virtual hosts
    - check for reverse dns (PTR ?)
    - Check CN's in protocoles' certificates (ssh, ftps....)
    - Add FQDN databases lookup
    
 - Configuration file :
    - Add a real configuration file (give possibility to remove github repos, pastes, downloaded files (if there are no warning words in them) merging all existing files
 
 - Final :
    - Search on the deep web
    - Threads files downloads and modules so that they can work in parrallel
    - Get ride of the API's (especially the whatcms api and the hunter/rocketreach)
    - Add the possibility to use some modules with a list of domains (at least --sublist/--subrute and --harvest)
