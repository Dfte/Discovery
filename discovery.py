#####################
# Imported libraries
#####################
import io
import os
import re
import sys
import time
import nmap
import json
import socket
import shodan
import dns.zone
import requests
import argparse
import dns.query
import sublist3r
import pythonwhois
import dns.resolver
from random import randint
from bs4 import BeautifulSoup
from signal import signal, SIGINT
from subprocess import check_output

###################################
# VARIABLES THAT YOU SHOULD MODIFY
###################################

##########################################################################
# Get Shodan API key by creating an account here : https://www.shodan.io/
##########################################################################
shodan_api_key = ""

############################################################################
# Get WhatCMS API key by creating an account here : https://whatcms.org/API
############################################################################
whatcms_api_key = ""

#####################################################################
# Get Hunter API key by creating an account here :https://hunter.io/
#####################################################################
hunter_api_key = ""

###################################################################################
# Get RocketReach API key by creating an account here : https://rocketreach.co/api
###################################################################################
rocketreach_api_key = ""

##################################
# DON'T MODIFY ANYTHING ELSE :D ! 
##################################

#########################################################################
# These are the global variables used to store emails and names gathered
# DON'T DELETE THEM
#########################################################################
emails = []
firstname_lastname = []
flastname = []
lfirstname = []
lastname_firstname = []
names = []
software = []
author = []
last_save = []

########################
# Colors code variables
########################
white = "\033[1;37m"
grey = "\033[0;37m"
purple = "\033[0;35m"
red = "\033[1;31m"
green = "\033[1;32m"
yellow = "\033[1;33m"
purple = "\033[0;35m"
end = "\033[m"

######################################
# This function will print the banner
######################################
def banner() :
	print("""{0}
          |-|-|      |
            |        |
            '--|     |	    Written By Defte
        _.-='  |\   /|\\
       |    |  |-'-'-'-'-.   Twitter : https://twitter.com/DefteWFfr/
       |_.-='  '========='   Website : https://whiteflag.blog
            `   |     |      Github  : https://github.com/Dfte
             `. |    / \\
               ||   /   \____.--=''''==--.._
               ||_.'--=='    |__  __  __  _.'
               ||  |    |    |\ ||  ||  || |                        ___
  ____         ||__|____|____| \||__||__||_/    __________________/|   |
 |    |______  |===.---. .---.========''''=-._ |     |     |     / |   |
 |    ||     |\| |||   | |   |      '===' ||  \|_____|_____|____/__|___|
 |-.._||_____|_\___'---' '---'______....---===''======//=//////========|
 |---------------------------------------------------------------------/
 |  8888b.  88 .dP"Y8  dP""b8  dP"Yb  Yb    dP 888888 88""Yb Yb  dP   /
 |   8I  Yb 88 `Ybo." dP   `" dP   Yb  Yb  dP  88__   88__dP  YbdP   /
 |   8I  dY 88 o.`Y8b Yb      Yb   dP   YbdP   88""   88"Yb    8P   /
 |  8888Y"  88 8bodP'  YboodP  YbodP     YP    888888 88  Yb  dP   /
 |= 1602 ============================================== v1.0 =====/
 '----------------------------------------------------------------`
		{1}""".format(yellow, end))
	return

########################################################################
# This function will gather informations from whois databases and parses
# the result to show you importants informations
########################################################################
def get_whois(domain):
	dns_servers = []
	data = ""
	print("{0}[#] Querying whois databases{1}".format(white, end))
	values = pythonwhois.get_whois(domain)
	if len(values) > 0 :
		for value in values :
			if value == "nameservers":
				for server in values[value] :
					server = server.lower()
					if server not in dns_servers :
						dns_servers.append(server)
					data += "\t{0}DNS Server : {1}{2}\n".format(green, server, end)
			if value == "registrar" :
				data += "\t{0}Registrar : {1}{2}\n".format(green, str(values[value][0]), end)
			if value == "contact" :
				data += "\t{0}Contact : {1}{2}\n".format(green, str(values[value][0]), end)
	print(data)
	output_write = open("{0}/whois/results".format(domain), "w+")
	print("{0}\t[!] Whois informations written in {1}/whois/results{2}\n".format(red, domain, end))
	return dns_servers

################################################################################################
# This function will try to achieve DNS transfert, query DNS'su sing dig and parses the results
################################################################################################
def dns_info(domain, dns_servers):
	print("{}[#] Gathering informations using DNS queries.{}".format(white, end))
	data = "{0}".format(green)
	records = ["A", "AAAA", "SOA", "NS", "MX", "TXT"]
	for record in records :
		try :
			values = dns.resolver.query(domain, record)
			if values :
				for value in values:
						if record == "A" :
							data += "\tRecord A    : {0}\n".format(value)
						if record == "AAAA" :
							data += "\tRecord AAAA : {0}\n".format(value)
						if record == "MX" :
							data += "\tRecord MX   : {0}\n".format(str(value.exchange).rsplit(".", 1)[0])
						if record == "SOA" :
							data += "\tRecord SOA  : {0}\n".format(str(value.mname).rsplit(".", 1)[0])
						if record == "NS" :
							data += "\tRecord NS   : {0}\n".format(str(value).rsplit(".", 1)[0])
							if str(value).rsplit(".", 1)[0] not in dns_servers :
								dns_servers.append(str(value).rsplit(".", 1)[0])
						if record == "TXT" :
							data += "\tRecord TXT  : {0}\n".format(str(value).rsplit(".", 1)[0])
		except :
			print("{0}\tNo record {1} found.{2}".format(red, record, end))
			pass
	print(data + "{0}".format(end))
	print("\t{0}[!] Full dig report written in {1}/dns/dig{2}\n".format(red, domain, end))
	if len(dns_servers) > 0 :
		print("{}[#] Testing for DNS zone transfert.{}".format(white, end))
		for dns_server in dns_servers :
			if dns_server :
				try :
					result  = dns.zone.from_xfr(dns.query.xfr(dns_server, domain))
					print("{0}\t-DNS zone transfer successful for {1}{2}".format(green, dns_server, end))
					write_to_file = open("{0}/dns/{1}.transfert".format(domain, dns_server), "w+")
					write_to_file.write(output)
					write_to_file.close()
					print("{0}\t\tResults written in {1}/dns/{2}".format(red, domain, dns_server))
				except  :
					print("{0}\t{1} : failed.{2}".format(red, dns_server, end))
	output_write = open("{0}/dns/dig".format(domain), "w+")
	output_write.write(data)
	output_write.close()
	print("")
	return

############################################################################
# This function will try to enumerate subdomains using Sublist3r tool.
# Depending of your wil, you can activate bruteforce module or not. Anyway,
# huge shout out to aboul3la for this tool !
# Github : https://github.com/aboul3la/Sublist3r
############################################################################
def get_domains(domain) :
	if args.subrute is not None :
		print("{0}[#] Launching Sublist3r with bruteforce module enabled.{1}".format(white, end))
		text_trap = io.StringIO()
		sys.stdout = text_trap
		sublist3r.main(domain, 100, "{0}/dns/{0}.domains".format(domain), ports = None, silent = True, verbose = False, enable_bruteforce = True, engines = None)
		sys.stdout = sys.__stdout__
	if args.sublist is not None :
		print("{0}[#] Launching Sublist3r with bruteforce module disabled.{1}".format(white, end))
		text_trap = io.StringIO()
		sys.stdout = text_trap
		sublist3r.main(domain, 100, "{0}/dns/{0}.domains".format(domain), ports = None, silent = True, verbose = False, enable_bruteforce = False, engines = None)
		sys.stdout = sys.__stdout__
	domain_file = open("{0}/dns/{0}.domains".format(domain), "r")
	domains = domain_file.readlines()
	domains.insert(0, domain + "\n")
	domain_file.close()
	domain_file = open("{0}/dns/{0}.domains".format(domain), "w")
	for line in domains :
		if line.startswith("www.") :
			wwwless = line.split("www.")[1]
			domains.remove(line)
			domains.append(wwwless)
	domains = set(domains)
	domain_file.writelines(domains)
	domain_file.close()
	print("{0}\tFound {1} domains : \n\t{2}{3}".format(green, len(domains), "\t".join(map(str, domains)), end))
	print("\t{0}[!] List of {1} domains written in {1}/dns/{1}.domains{2}\n".format(red, len(domains), domain, end))
	return

##########################################################################
# Using gethostnyname() from the socket librairy, this function will find
# domains linked to an IP
##########################################################################
def from_domains_to_ips(domain) :
	save_domain = domain
	ips = []
	print("{0}[#] Translating domain names to IP's.{1}".format(white, end))
	domains = open("{0}/dns/{0}.domains".format(domain), "r")
	output = open("{0}/dns/{0}.domains_to_ips".format(domain), "w+")
	output2 = open("{0}/dns/{0}.ips".format(domain), "w+")
	for domain in domains :
		domain = domain.replace("\n", "")
		try :
			ip = socket.gethostbyname(domain)
			line_to_write = domain + " || " + ip + "\n"
			output.write(line_to_write)
			if ip not in ips :
				output2.write(ip + "\n")
				ips.append(ip)
		except :
			pass
	domains.close()
	output.close()
	print("\n\t{0}[!] IP's, domains and IP's to domains file written in {1}/dns/{2}\n".format(red, save_domain, end))
	return

#############################################################################
# This function will first launch a nmap scan on all ips/domains detected
# or on the in scope domains/ips. Depending of the result a few others tools
# will be used (sslscan for testing ssl certificats), whatcms API to detect
# CMS's used or WAFw00f tool to detect potential WAF's.
# Github : https://github.com/EnableSecurity/wafw00f
#############################################################################
def scanner(domain, level) :
	data = ""
	files = []
	source_files = open("configuration/warning_files".format(domain), "r")
	for warning_file in source_files.readlines() :
		warning_file = warning_file.replace("\n", "")
		files.append(warning_file)
	source_files.close()
	print("{0}[#] Scanning found IP's {1}\n".format(white, end))
	ips = open("{0}/dns/{0}.ips".format(domain), "r")
	ips = ips.readlines()
	for ip in ips :
		ip = ip.replace("\n", "")
		os.system("mkdir {0}/scan/{1}".format(domain, ip))
		nm = nmap.PortScanner()
		if level == "full" :
			print("{0}\tScanning {1} with Nmap (full scan){2}".format(white, ip, end))
			nm.scan(ip, arguments = "-sV -p- -Pn --open")
		if level == "fast" :
			print("{0}\tScanning {1} with Nmap (fast scan){2}".format(white, ip, end))
			nm.scan(ip, arguments = "-sV -F -Pn --open")
		if len(nm.all_hosts()) > 0 :
			for host in nm.all_hosts():
				data = "\t{0}----------------------------------------------------------------------------------{1}\n".format(white, end)
				data += "\t{0}Host : {1} ({2}){3}\n".format(green, host, nm[host].hostname(), end)
				data += "\t{0}State : {1}{2}\n".format(green, nm[host].state(), end)
				for proto in nm[host].all_protocols():
					data += "\t{0}----------{1}\n".format(white, end)
					data += "\t{0}Protocol : {1}{2}\n".format(white, proto, end)
					lport = nm[host][proto].keys()
					for port in lport :
						if "Apache" in nm[host]["tcp"][int(port)]["product"] or "Nginx" in nm[host]["tcp"][int(port)]["product"] or "IIS" in nm[host]["tcp"][int(port)]["product"] \
																																				or int(port) == 443 or int(port) == 80:
							if nm[host]["tcp"][int(port)]["name"] == "http" :
								url = "http://{0}:{1}/".format(ip, port)
							if nm[host]["tcp"][int(port)]["name"] == "https" :
								url = "https://{0}:{1}/".format(ip, port)
							data += "\t{0}port : {1}{2}{3}\tstate : {4}\tService : {5} {6}/{7}{2}\n".format(green, port, end, white, nm[host][proto][port]["state"], nm[host][proto][port]["name"], nm[host]["tcp"][int(port)]["product"], nm[host][proto][port]['version'])
							##########
							# WHATCMS
							##########
							if whatcms_api_key is not "" :
								request =  requests.get("https://whatcms.org/APIEndpoint/Detect?key={0}&url={1}".format(whatcms_api_key, url))
								if request.status_code == 200 :
									cms_info = json.loads(request.text)
									if cms_info["result"]["name"] is not None :
										data +="\t\t{0}CMS detected : {1} (accuracy : {2}){3}\n".format(red, cms_info["result"]["name"], cms_info["result"]["confidence"], end)
							##########
							# SSLscan
							##########
							if nm[host]["tcp"][int(port)]["name"] == "https" :
								try:
									output = check_output(["sslscan", "{0}".format(url)])
									output = output.decode('ascii')
									buf = io.StringIO(output).read()
									if "is vulnerable to heartbleed" in buf :
										data += "{0}\t\t Heartbleed vulnerability detected !{1}\n".format(red, end)
									os.system("mkdir {0}/scan/{1}/".format(domain, ip))
									output_write = open("{0}/scan/{1}/sslscan".format(domain, ip), "w+")
									output_write.write(buf)
									output_write.close()
									data += "\t\t{0}SSLscan saved in {1}/scan/{2}/sslscan{3}\n".format(green, domain, ip, end)
								except :
									pass
							#################
							###WAF DETECTION
							#################
							try :
								output = check_output(["wafw00f", "{0}".format(url)])
								output = output.decode('ascii')
								if "No WAF detected" in output :
									data += "\t\t{0}No WAF detected{1}\n".format(green, end)
								else :
									data += "\t\t{0}WAF detected ! Check output in {1}/scan/{2}/waf_detection{3}\n".format(red, domain, ip, end)
								output_write = open("{0}/scan/{1}/waf_detection".format(domain, ip), "w+")
								output_write.write(output)
								output_write.close()
							except :
								pass
							################################
							###Detection of sensitive files
							################################
							for important_file in files :
								request =  requests.get(url + "{0}".format(important_file))
								if request.status_code == 200 :
									data += "\t\t{0}Found {1} file on {2}{1} -> downloaded !{3}\n".format(red, important_file, url, end)
									os.system("mkdir {0}/scan/{1}/sensitive_files/".format(domain, ip))
									if important_file.startswith(".") :
										important_file = important_file.split(".")[1]
									write_to = open("{0}/scan/{1}/sensitive_files/{2}".format(domain, ip, important_file), "w+")
									write_to.write(request.text)
									write_to.close()
						else :
							data += "\t{0}port : {1}{2}\t{4}state : {3}\tService : {5}/{6}{2}\n".format(green, port, end, nm[host][proto][port]["state"], white, nm[host]["tcp"][int(port)]["product"], nm[host]["tcp"][int(port)]["version"])
			data += "\t{0}----------------------------------------------------------------------------------{1}".format(white, end)
			print(data)
			written_to = open("{0}/scan/{1}/nmap.txt".format(domain, ip), "w+")
			written_to.write(data)
			written_to.close()
			written_to = open("{0}/scan/{1}/nmap.xml".format(domain, ip), "w+")
			written_to.write(nm.get_nmap_last_output())
			written_to.close()
	return

##########################################################################
# This function will gather informations from the shodan API's : detected
# servers, versions, CVE related to the possible flaws
##########################################################################
def scrape_shodan(domain):
	print("{0}[#] Gathering informations from Shodan's API.{1}\n".format(white, end))
	data = ""
	api = shodan.Shodan(shodan_api_key)
	targets = open("{0}/dns/{0}.ips".format(domain), "r")
	for target in targets :
		target = target.replace("\n", "")
		target = re.findall( r'[0-9]+(?:\.[0-9]+){3}', target)
		try:
			results = api.search(target[0])
			if results["total"] == 0 :
				pass
			else :
				for result in results["matches"]:
					data += "{0}\tIP : {1}{2}\n".format(green, result["ip_str"], end)
					if "product" in result and "version" in result :
						data += "{0}\tServer : {1} {2}{3}\n".format(green, result["product"], result["version"], end)
					if "location" in result and result["location"]["country_name"] is not None :
						data += "{0}\tLocation : {1}{2}\n".format(green, result["location"]["country_name"], end)
					if "vulns" in result and result["vulns"] is not None :
						data += "{0}\tVulnérabilities : {1}\n".format(red, end)
						for cve in result["vulns"] :
							url = "https://www.cvedetails.com/cve/{0}".format(cve)
							cve_details = requests.get(url)
							if cve_details.status_code == 200 :
								soup = BeautifulSoup(cve_details.text, 'html.parser')
								desc = soup.find("div", {"class" : "cvedetailssummary" })
								if desc is not None :
									desc = re.sub(r'\n\s*\n', r'\n\n', desc.get_text().strip(), flags = re.M)
									desc = desc.split("\n")[0]
									data += "\t\t{0}{1} : {2}\n\t\t{3}{4} {5}\n\n".format(red, cve , url, white, "\n\t\t".join(textwrap.wrap(desc, width = 60)),  end)
								else :
									data += "\t\t{0}{1} : {2} {3}\n\n".format(red, cve, "No informations found", end)
							else :
								data += "\t{0}{1} : {2} {3}\n\n".format(red, cve, "No information found", end)
					else :
						data += "{0}\tNo vulnerabilities found...{1}\n\n".format(red, end)
		except shodan.APIError as e:
			pass
	print(data)
	summary = open("{0}/shodan/results".format(domain),"w+")
	summary.write(data)
	summary.close()
	print("{0}\t[!] Reports written in {1}/scan/{2}/shodan{3}\n".format(red, domain, target[0], end))
	return

##########################################################################
# This function will crawl as much as possible Google to gather files
# publicly exposed by the domain you're looking for. It will retrieve pdf
# xls, docx, doc and so on... And will then try to parse the documents to
# gather sensitives datas. This function is partially inspired from the
# pyfoca script written by altjx
# Github : https://github.com/altjx/ipwn/tree/master/pyfoca
###########################################################################
def documents_gathering(domain, max_scrape):
	global author
	global software
	global last_save
	print("{0}[#] Gathering documents using Google Dorks.{1}".format(white, end))
	links = []
	files = []
	save_domain = domain
	headers = {
		"Accept": "*/*",
		"Accept-Language": "en-US;q=0.9",
		"Cache-Controle": "max-age=0",
		"Connection": "keep-alive",
		"Host": "www.google.com",
		"Referer": "https://www.google.com/",
		"User-Agent": "Mozilla/5.0 (X11; Linux i686; rv:64.0) Gecko/20100101 Firefox/64.0",
	}
	exts = open("configuration/extensions", "r")
	list_name = open("{0}/harvest/doc_usernames".format(domain), "w+")
	for ext in exts.readlines() :
		count = 0
		found = 0
		ext = ext.replace("\n", "")
		while 1 :
			query = "https://www.google.com/search?q=site:{0}+ext:{1}&start={2}&num=100".format(domain, ext, count)
			request = requests.get(query, headers = headers)
			if request.status_code == 503 :
				print("\n\t{0}[!] We got blocked by Google stopping the crawl...{1}\n".format(red, end))
				return
			soup = BeautifulSoup(request.text, 'html.parser')
			urls_pattern = "(?P<url>https?://[^:]+\.%s)" % ext
			found_urls = re.findall(urls_pattern, str(soup))
			try :
				for url in found_urls :
					if url not in links :
						links.append(url)
						found += 1
						name_file = url.split("/")[-1]
						name_file = name_file.split("{0}&".format(ext))[0]
						files.append(name_file)
						request = requests.get(url, stream = True)
						file_path = "{0}/document/{1}/{2}".format(save_domain, ext, name_file)
						write_file = open(file_path, "wb+")
						for chunk in request.iter_content(4096):
							write_file.write(chunk)
						write_file.close()
						parse(save_domain, file_path, name_file)
						sys.stdout.write('\r')
						sys.stdout.write("{0}\tDownloaded {1} out of {2} .{3} files{4}\n".format(green, found, len(found_urls), ext, end))
						sys.stdout.flush()
				time.sleep(randint(20, 30))
				found = 0
				found_urls = 0
				if count == 0 :
					count += 2
				else :
					count += 1
				buttons = soup.findAll("a", {"class" : "fl" })
				page = []
				for button in buttons :
					button = re.sub(r'\n\s*\n', r'\n\n', button.get_text().strip(), flags = re.M)
					page.append(button)
				if str(count) not in page :
					break
			except Exception as e :
				print(e)
				pass
	print("\n\t{0}[!] {1} documents downloaded and stored in {2}/document/.{3}\n".format(red, len(links), save_domain, end))
	list_name.close()
	if len(author) > 0 :
		output_write = open("{0}/document/metadatas_resume/authors".format(domain), "w+")
		for auth in author :
			output_write.write(auth + "\n")
		output_write.close()
	if len(software) > 0 :
		output_write = open("{0}/document/metadatas_resume/softwares".format(domain), "w+")
		for soft in software :
			output_write.write(soft + "\n")
		output_write.close()
	if len(last_save) > 0 :
		output_write = open("{0}/document/metadatas_resume/last_saves".format(domain), "w+")
		for last in last_save :
			output_write.write(last + "\n")
		output_write.close()
	print("{0}\t[!] Metadatas reports stored in : {1}/document/metadata_*.{2}\n".format(red, save_domain, end))
	return

#######################################################################
# This function will use the exiftool librairye extract metadatas from
# files. Gather author name, software used to create the file and
# the name/date of the last save.
######################################################################
def parse(domain, path, name) :
	global software
	global author
	global last_save
	output = check_output(["exiftool", "-j", "{0}".format(path)])
	output = json.loads(output)
	output_write = open("{0}/document/metadatas_full/{1}".format(domain, name), "w+")
	for info, value in output[0].items() :
		if "Author" in str(info) and str(value) not in author :
			author.append(str(value))
		if "Software" in str(info) and str(value) not in software :
			software.append(str(value))
		if "LastSavedBy" in str(info) and str(value) not in last_save :
			last_save.append(str(value))
		output_write.write(str(info) + " : " + str(value) + "\n")
	output_write.close()

#########################################################################
# This function will look on hunter.io API to find emails related to the
# domain you're working on.
#########################################################################
def hunter(domain) :
	print("{}[#] Querying hunter.io API.{}\n".format(white, end))
	output_write = open("{0}/harvest/hunter".format(domain), "w+")
	request = requests.get("https://api.hunter.io/v2/domain-search?domain={0}&api_key={1}".format(domain, hunter_api_key))
	if request.status_code == 200 :
		results = json.loads(request.text)
		for item in results["data"]["emails"] :
			output_write.write(item["value"] + "\n" )
	else :
		pass
	print("\t{0}[!] Result written in {1}/harvest/hunter{2}\n".format(red, domain, end))
	return

#########################################################################
# This function will look on rocketreach API to gather names of employee
#  working for the company you're gathering informations on. Then it will
# parse the output to create a list of names that will be used later.
# Shoutout to my friend N3tsky who wrote the orgininal API parser script
# that i took as an exemple to create this function :
# Github : https://github.com/n3tsky/PeopleScrap
#########################################################################
def rocketreach(domain) :
	global names
	page_start = 1
	page_size = 100
	current_page = 0
	next_page = 1
	print("{}[#] Querying rocketreach.co API.\n{}".format(white, end))
	while current_page != next_page :
		url = "https://api.rocketreach.co/v1/api/search?api_key={0}&company={1}&page_size={2}&start={3}".format(rocketreach_api_key, domain.split(".")[0], page_size, next_page)
		request = requests.get(url)
		if request.status_code == 200 :
			json_data = json.loads(request.text)
			for profile in json_data["profiles"] :
				names.append(str(profile["name"]))
			if json_data != None:
				if "pagination" in json_data :
					pagination = json_data["pagination"]
					current_page = pagination["thisPage"]
					next_page = pagination["nextPage"]
	print("{0}\t [!] List of {1} names retrieved !{2}\n".format(red, len(names), end))
	return

#############################################################################
# This function will create a list of emails from the previously found names
# In order for it to work, the script must first detect the pattern of an
# original and validated emails of the company so that there are no mistakes
#############################################################################
def mail_list_creator(domain) :
	global emails
	global names
	global firstname_lastname
	global flastname
	global lfirstname
	global lastname_firstname
	print("{0}[#] Creating email lists !{1}".format(white, end))
	for name in names :
		# A changer
		isascii = lambda name: len(name) == len(name.encode())
		#######################################################
		if name != "" and isascii(name) == True :
			name = name.lower()
			try :
				firstname, lastname, *rest = name.split(" ")
			except :
				pass
			if firstname != "" and lastname != "" :
				firstname_lastname.append("{0}.{1}@{2}".format(firstname, lastname, domain))
				lastname_firstname.append("{0}.{1}@{2}".format(lastname, firstname, domain))
				flastname.append("{0}{1}@{2}".format(firstname[0], lastname, domain))
				lfirstname.append("{0}{1}@{2}".format(lastname[0], firstname, domain))
	return

##########################################################################
# This function will write all names/emails found on files in the harvest
# directory.
##########################################################################
def write_all(domain) :
	global emails
	global names
	global firstname_lastname
	global flastname
	global lfirstname
	global lastname_firstname
	output_firstname_lastname = open("{0}/harvest/firstname_lastname".format(domain), "w+")
	for mail in firstname_lastname :
		output_firstname_lastname.write(mail + "\n")
	output_firstname_lastname.close()
	output_lastname_firstname = open("{0}/harvest/lastname_firstname".format(domain), "w+")
	for mail in lastname_firstname:
		output_lastname_firstname.write(mail + "\n")
	output_lastname_firstname.close()
	output_flastname = open("{0}/harvest/flastname".format(domain), "w+")
	for mail in flastname:
		output_flastname.write(mail + "\n")
	output_flastname.close()
	output_lfirstname = open("{0}/harvest/lfirstname".format(domain), "w+")
	for mail in lfirstname:
		output_lfirstname.write(mail + "\n")
	output_lfirstname.close()
	output_names = open("{0}/harvest/names".format(domain), "w+")
	for name in names :
		output_names.write(name + "\n")
	output_names.close()
	print("\n\t{0}[!] List of {1} emails names written in {2}/harvest/.{3}\n".format(red, len(firstname_lastname), domain, end))
	return

def interruptHandler(signal, frame):
	print("{0}\n[!] User interruption... Leaving ! :) !{1}\n".format(red, end))
	signature()
	sys.exit(0)
	return

def signature() :
	print('''{0}
         _          _     _       __                                           _
   /\/\ (_)___  ___| |__ (_) ___ / _|   /\/\   __ _ _ __   __ _  __ _  ___  __| |
  /    \| / __|/ __| '_ \| |/ _ \ |_   /    \ / _` | '_ \ / _` |/ _` |/ _ \/ _` |
 / /\/\ \ \__ \ (__| | | | |  __/  _| / /\/\ \ (_| | | | | (_| | (_| |  __/ (_| |
 \/    \/_|___/\___|_| |_|_|\___|_|   \/    \/\__,_|_| |_|\__,_|\__, |\___|\__,_|
                                                                |___/
	{1}'''.format(red,end))
	return

#######################
# Clearing the terminal
#######################
os.system("clear")
banner()
signal(SIGINT, interruptHandler)

#########################################
# Use argparse module to parse arguments
# Also it verifies the arguments values
#########################################
parser = argparse.ArgumentParser()
parser.add_argument("-d", help = "Single domain to perform recon on.", dest = "single_domain")
parser.add_argument("--dns", help = "Query DNS's and launch DNS transfert attack.", nargs = "?", const = "yes", dest = "dns")
parser.add_argument("--sublist", help = "Launch DNS enumeration without bruteforce modules.", nargs = "?", const = "yes", dest = "sublist")
parser.add_argument("--subrute", help = "Launch DNS enumeration with bruteforce module enable.", nargs = "?", const = "yes", dest = "subrute")
parser.add_argument("--scan", help = "Type of scan : fast = 1000 first ports, all = 65653 ports.", choices = ["full", "fast",], dest = "scan")
parser.add_argument("--gather", help = "Will download and check for metadats in files.", nargs = "?", const = "yes", dest = "gather")
parser.add_argument("--harvest", help = "Will create multiples lists of email addresses using differents API's.", nargs = "?", const = "yes", dest = "harvest")
args = parser.parse_args()
#if (not args.sublist or not args.subrute) and args.scan :
#	sys.exit("{0}[!] You need to enable --sublist or --subrute module to use --scan{1}".format(red, end))

##################################
#The most important variable :D !
##################################
domain = args.single_domain

############################
# Creating output structure
############################
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.isdir(current_dir + "/" + domain) :
	pass
else :
	os.system("mkdir {0}".format(domain))
	os.system("mkdir {0}/dns {0}/document {0}/shodan {0}/harvest {0}/scan {0}/whois {0}/document/metadatas_full {0}/document/metadatas_resume".format(domain))
	extensions = open("configuration/extensions").readlines()
	for ext in extensions :
		ext = ext.replace("\n", "")
		os.system("mkdir {0}/document/{1}".format(domain, ext))

#######################################
# That's basically the script backbone
#######################################
#try :
if args.dns :
	dns_servers = get_whois(domain)
	dns_info(domain, dns_servers)
if args.subrute or args.sublist :
	get_domains(domain)
	from_domains_to_ips(domain)
	#if args.scan :
		#scanner(domain, args.scan)
		#if shodan_api_key is not "" :
			#scrape_shodan(domain)
if args.scan :
		scanner(domain, args.scan)
		if shodan_api_key is not "" :
			scrape_shodan(domain)
if args.gather :
	documents_gathering(domain, args.gather)
if args.harvest and hunter_api_key is not "" and rocketreach_api_key is not "" :
	hunter(domain)
	rocketreach(domain)
	mail_list_creator(domain)
	write_all(domain)
#except Exception as e:
#	print("{0}[!] An error occured... Please contact me and paste the following trace so that I can fix it :) !\n{1}".format(red, end))

############################
# Print signature banner :D
############################
signature()
