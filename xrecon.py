import shodan
import sys
from prettytable import PrettyTable
import time
import re
import os
from subprocess import check_output
import logo
import zoomeye
import json
import itertools
import requests
import json
from itertools import izip_longest


def searchshodan():
	print ("##########################################################################")
	logo.shodanlogo()
	print ("##########################################################################")
	time.sleep(1)
	# Configuration
	API_KEY = "APIKEY HERE"
	z = PrettyTable()
	z.field_names = ["Count", "IP", "OS", "Hostnames", "Port"]
	j = 1
	k = 1
	f = open('search.txt')
	for x in f.readlines():
		time.sleep(1.1)
		print x.rstrip()  

		try:
	        # Setup the api
			api = shodan.Shodan(API_KEY)

	        # Perform the search
			query = ' '.join(sys.argv[1:])
			#print str(k)+ ' ' + x.rstrip()
			k = k+1
			result = api.search(x.rstrip())

	        # Loop through the matches and print each IP
			for service in result['matches']:
					ip = service['ip_str']
					os = service['os']
					hostname = service['hostnames']
					port = service['port']
					data = service['data']
					
					#print ip
					z.add_row([j, ip, os, hostname, port])
					j = j+1
		except Exception as e:
			print 'Error: %s' % e
			#sys.exit(1)
		table_txt = z.get_string()
		with open('table.txt',"a") as file:
			file.write("\n")
			file.write(x)
			file.write(table_txt)
		
		print z
		file.close()
		f.close()
def searchzoomeye():
	logo.zoomeyelogo()
	dir(zoomeye)
	zm = zoomeye.ZoomEye()
	zm.username = 'USERNAME'
	zm.password = 'PASSWORD'
	zm.login()


	f = open('search.txt')
	for x in f.readlines():
		time.sleep(0)
		#print x.rstrip()  
		data = zm.dork_search(x)
		print ('*')*95
		strdata = str(data)
		ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', strdata )
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', strdata)
		with open('table.txt',"a") as file:
			file.write("\n")
			file.write("*****************ZoomEye Google Dorks***************************")
			file.write("\n")
			for x in ip:
				print x
				file.write("\n")
				file.write(x)
def fetchip():
	print ("##########################################################################")
	logo.fetchiplogo()
	time.sleep(1)
	print ("##########################################################################")

	f = open('table.txt')
	for user in f.readlines():
		line = user
		regex = r"(\d+)(.)(\d+)(.)(\d+)(.)(\d+)"
		x = re.search(regex, line)
		if x:
			print x.group(0)
			with open('ip_list.txt',"a") as file:
				file.write(x.group(0))
				file.write("\n")
	file.close()
def normalize():
	print ("##########################################################################")
	logo.normalizinglogo()
	time.sleep(1)
	print ("##########################################################################")
	f = open("ip_list.txt")
	x = []
	for m in f.readlines():
		x.append(m.rstrip())
	n = []
	n = list(set(x))
	#print (*n, sep = "\n")
	print '---------------'
	print 'Unique_Total ' + str(len(set(x)))
	print '---------------'
	with open('normalized_ip_list.txt',"a") as file:
		for x in n:
			print x
			file.write(x)
			file.write("\n")
	file.close()
	f.close()

	check_output("del ip_list.txt", shell=True)
def ipgeo():
	print ("##########################################################################")
	logo.ipgeologo()
	time.sleep(1)
	print ("##########################################################################")
	z = PrettyTable()
	z.field_names = ["Input", "Host", "IP", "rDNS", "Country", "Region" ,"City", "Postal Code"]
	f = open('normalized_ip_list.txt')
	for g in f.readlines():
		time.sleep(1)
		print g.rstrip() 
		
		try:
			r = requests.get('https://tools.keycdn.com/geo.json?host=' + g.rstrip())
			x = r.json()
			ip = x['data']['geo']['ip']
			rdns = x['data']['geo']['rdns']
			country = x['data']['geo']['country_code']
			region = x['data']['geo']['region']
			city = x['data']['geo']['city']
			postal_code = x['data']['geo']['postal_code']
			host = x['data']['geo']['host']


			z.add_row([g.rstrip(), host , ip , rdns , country , region, city, postal_code])
		except Exception as e:
		 	z.add_row([g.rstrip() , '-', '-', '-', '-', '-', '-', '-'])

	print z
	table_txt = z.get_string()
	encoded = table_txt.encode('utf-8')
	with open('ip_geolocation.txt',"a") as file:
		file.write("\n")
		file.write(encoded)
def main():
	searchshodan()
	searchzoomeye()
	fetchip()
	normalize()
	ipgeo()


main()
