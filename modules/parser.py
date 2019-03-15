import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
import json

try:
	connection = mysql.connector.connect(host='localhost', database='fdns', user='',password='')
except mysql.connector.Error as error:
	print("Error {0}".format(error))

#file = open("entry.txt", "r+")
#for line in file.readlines() :
#	string = line.replace("\n", "")
string='{"timestamp":"1550794171","name":"0.175.17.109.rev.sfr.net","type":"a","value":"109.17.175.0"}'
load = json.loads(string)
if load["name"] :
	name = load["name"]
	if load["type"] :
		typ = load["type"]
		if load["value"]:
			value = load["value"]
		cursor = connection.cursor()
		sql_insert_query = "insert into entry (dns_entry, type, value) values ('{0}', '{1}', '{2}');".format(str(name), str(typ), str(value))
		result  = cursor.execute(sql_insert_query)
		connection.commit()
		print(name, typ)

		{"timestamp":"1550794171","name":"0.175.17.109.rev.sfr.net","type":"a","value":"109.17.175.0"}
{"timestamp":"1550794170","name":"0.175.170.89.rev.sfr.net","type":"a","value":"89.170.175.0"}
{"timestamp":"1550794102","name":"0.175.174.95.rev.sfr.net","type":"a","value":"95.174.175.0"}
{"timestamp":"1550794438","name":"0.175.175.95.rev.sfr.net","type":"a","value":"95.175.175.0"}
{"timestamp":"1550794152","name":"0.175.18.109.rev.sfr.net","type":"a","value":"109.18.175.0"}
{"timestamp":"1550794469","name":"0.175.18.135.in-addr.arpa","type":"a","value":"135.18.175.0"}
{"timestamp":"1550794469","name":"0.175.18.135.in-addr.arpa","type":"ptr","value":"0.175.18.135.in-addr.arpa"}
{"timestamp":"1550794279","name":"0.175.18.212.rev.vodafone.pt","type":"a","value":"212.18.175.0"}
{"timestamp":"1550794359","name":"0.175.18.93.rev.sfr.net","type":"a","value":"93.18.175.0"}
{"timestamp":"1550794565","name":"0.175.180.213.static.wline.lns.sme.cust.swisscom.ch","type":"a","value":"213.180.175.0"}
{"timestamp":"1550794174","name":"0.175.184.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794116","name":"0.175.184.35.bc.googleusercontent.com","type":"a","value":"35.184.175.0"}
{"timestamp":"1550794179","name":"0.175.185.135.in-addr.arpa","type":"a","value":"135.185.175.0"}
{"timestamp":"1550794179","name":"0.175.185.135.in-addr.arpa","type":"ptr","value":"0.175.185.135.in-addr.arpa"}
{"timestamp":"1550794328","name":"0.175.185.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794320","name":"0.175.185.203.dsl.dyn.mana.pf","type":"a","value":"203.185.175.0"}
{"timestamp":"1550794308","name":"0.175.185.35.bc.googleusercontent.com","type":"a","value":"35.185.175.0"}
{"timestamp":"1550794385","name":"0.175.185.80.rev.sfr.net","type":"a","value":"80.185.175.0"}
{"timestamp":"1550794376","name":"0.175.185.81.rev.sfr.net","type":"a","value":"81.185.175.0"}
{"timestamp":"1550794343","name":"0.175.185.89.rev.sfr.net","type":"a","value":"89.185.175.0"}
{"timestamp":"1550794119","name":"0.175.186.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794485","name":"0.175.186.35.bc.googleusercontent.com","type":"a","value":"35.186.175.0"}
{"timestamp":"1550794286","name":"0.175.187.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550795462","name":"0.175.187.35.bc.googleusercontent.com","type":"a","value":"35.187.175.0"}
{"timestamp":"1550794228","name":"0.175.187.81.in-addr.arpa","type":"a","value":"81.187.175.0"}
{"timestamp":"1550794228","name":"0.175.187.81.in-addr.arpa","type":"ptr","value":"0.175.187.81.in-addr.arpa"}
{"timestamp":"1550794227","name":"0.175.188.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794543","name":"0.175.188.35.bc.googleusercontent.com","type":"a","value":"35.188.175.0"}
{"timestamp":"1550794127","name":"0.175.189.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794247","name":"0.175.189.35.bc.googleusercontent.com","type":"a","value":"35.189.175.0"}
{"timestamp":"1550794230","name":"0.175.189.46.rev.vodafone.pt","type":"a","value":"46.189.175.0"}
{"timestamp":"1550794812","name":"0.175.189.80.dyn.plus.net","type":"a","value":"80.189.175.0"}
{"timestamp":"1550794277","name":"0.175.19.109.rev.sfr.net","type":"a","value":"109.19.175.0"}
{"timestamp":"1550794501","name":"0.175.19.93.rev.sfr.net","type":"a","value":"93.19.175.0"}
{"timestamp":"1550794161","name":"0.175.190.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794487","name":"0.175.190.35.bc.googleusercontent.com","type":"a","value":"35.190.175.0"}
{"timestamp":"1550794337","name":"0.175.191.183.adsl-pool.sx.cn","type":"cname","value":"adsl-pool.sx.cn.cdn.clsn.io"}
{"timestamp":"1550794457","name":"0.175.191.92.dynamic.jazztel.es","type":"a","value":"92.191.175.0"}
{"timestamp":"1550794170","name":"0.175.192.178.dynamic.wline.res.cust.swisscom.ch","type":"a","value":"178.192.175.0"}
{"timestamp":"1550794249","name":"0.175.192.35.bc.googleusercontent.com","type":"a","value":"35.192.175.0"}
{"timestamp":"1550794128","name":"0.175.192.77.rev.sfr.net","type":"a","value":"77.192.175.0"}
{"timestamp":"1550794403","name":"0.175.193.178.dynamic.wline.res.cust.swisscom.ch","type":"a","value":"178.193.175.0"}
{"timestamp":"1550794171","name":"0.175.193.35.bc.googleusercontent.com","type":"a","value":"35.193.175.0"}
{"timestamp":"1550794361","name":"0.175.193.77.rev.sfr.net","type":"a","value":"77.193.175.0"}
{"timestamp":"1550794960","name":"0.175.194.178.dynamic.wline.res.cust.swisscom.ch","type":"a","value":"178.194.175.0"}
{"timestamp":"1550794223","name":"0.175.194.35.bc.googleusercontent.com","type":"a","value":"35.194.175.0"}
{"timestamp":"1550794193","name":"0.175.194.77.rev.sfr.net","type":"a","value":"77.194.175.0"}
{"timestamp":"1550794418","name":"0.175.194.85.sta.ac-net.se","type":"a","value":"85.194.175.0"}
{"timestamp":"1550794451","name":"0.175.195.178.dynamic.wline.res.cust.swisscom.ch","type":"a","value":"178.195.175.0"}
{"timestamp":"1550794146","name":"0.175.195.35.bc.googleusercontent.com","type":"a","value":"35.195.175.0"}
