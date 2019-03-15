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
