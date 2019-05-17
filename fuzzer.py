#!/usr/bin/env python3
import requests        # for sending/receiving web requests
import sys             # various system routines (exit, access to stdin, stderr, etc.)
import itertools       # simple tools for computing, e.g., the cross-product of lists
import random 		   # for random generation
from enum import Enum  # for defining enumerations

class PayloadType(Enum):
	SQL_STATIC = 1 # fuzz with a pre-configured list of SQL payloads
	XSS_STATIC = 2 # fuzz with a pre-configured list of XSS payloads
	XSS        = 3 # fuzz with dynamically generated XSS payloads (mutations) 
	SQL        = 4 # fuzz with dynamically generated SQL payloads (mutations) 

class FuzzConfig:
	def __init__(self):
		# change url for different website
		self.app_root_url = "http://localhost:3000"

		# change the login endpoint to login to another website
		self.login_endpoint = {
			"url": "/sign_in",
			"param_data": {
				"login": "peter",
				"password": "football"
			}
		}

		# here we can add endpoints if we want to check more
		self.endpoints = [
			{
				"url": "/grades",
				"method": "GET",
				"require_login": False,
				"param_data": {},
				"cookie_data": {
					"session": [PayloadType.SQL],
				},
			},
			{
				"url": "/grades",
				"method": "GET",
				"require_login": True,
				"param_data": {
					"lecturer": [PayloadType.SQL]
				},
				"cookie_data": {},
			},
			{
				"url": "/sign_in",
				"method": "POST",
				"require_login": False,
				"param_data": {
					"login": [PayloadType.SQL],
					"password": [PayloadType.SQL_STATIC]
				},
				"cookie_data": {},
			},

			{
				"url": "/grades/1",
				"method": "POST",
				"require_login": True,
				"param_data": {
					"_method":"patch",
					"grade[comment]": [PayloadType.XSS_STATIC],
				},
				"cookie_data": {},
			},

		{
				"url": "/grades",
				"method": "POST",
				"require_login": True,
				"param_data": {
					"_method":"patch",
					"lecturer": [PayloadType.XSS],
				},
				"cookie_data": {},
			},
		]

# function for checking the static sql payloads
def static_sql(endpoint, payloads, r, key, data, url):
	injection = endpoint[data].copy()
	found = 0
	
	# change the number for different number of payloads used (max number should be len(payloads)).
	# comment this and uncomment the following for loop, if we want to use all the payloads
	for payload in random.sample(payloads, 20):
	#for payload in payloads:
		
		injection[key] = payload
		if data is "param_data":
			response = r.request(endpoint["method"],url, params = injection)
		else:
			response = r.request(endpoint["method"],url, cookies = injection)
		
		if response.status_code == 500 or response.status_code == 200 and "Login successful" in response.text:
			print("POSSIBLE SQL INJECTION with payload:", key, ":", payload)
			found += 1

	return found
# function for checking the mutated sql payloads
def mutate_sql(endpoint, payloads, r, key, data, url):
	injection = endpoint[data].copy()
	found = 0

	# change the number for different number of payloads used (max number should be len(payloads)).
	# comment this and uncomment the following for loop, if we want to use all the payloads
	for payload in random.sample(payloads, 20):
		#for payload in payloads:
		boolean = True
		# first check if the static payload is succesful
		injection[key] = payload
		if data is "param_data":
			response = r.request(endpoint["method"],url, params = injection)
		else:
			response = r.request(endpoint["method"],url, cookies = injection)
			
		if 500 == response.status_code or (200 == response.status_code and "Login successful" in response.text):
			print("POSSIBLE SQL INJECTION with payload:", key, ":", injection[key])
			found += 1
			boolean = False

		# if it is not succesful, mutate it until it is or until the max amount of mutations is reached
		i = 0
		while boolean and i < 10:
			injection[key] = mutate(payload, i%3)
			i += 1
			if data is "param_data":
				response = r.request(endpoint["method"],url, params = injection)
			else:
				response = r.request(endpoint["method"],url, cookies = injection)
				
			if 500 == response.status_code or (200 == response.status_code  and "Login successful" in response.text):
				print("POSSIBLE SQL INJECTION with payload:", key, ":", injection[key])
				found += 1
				boolean = False

	return found
# function for checking the static xss payloads
def static_xss(endpoint, payloads, r, key, data, url):
	injection = endpoint[data].copy()
	found = 0
	# get the source code from the page before trying any xss, to check your result
	initial = r.get(url)

	# change the number for different number of payloads used (max number should be len(payloads)).
	# comment this and uncomment the following for loop, if we want to use all the payloads
	for payload in random.sample(payloads, 20):
	#for payload in payloads:		
		injection[key] = payload
		response = r.request(endpoint["method"],url, data = injection)
		final = r.get(url)			

		if (initial.text != response.text and payload in response.text) or (final.text != initial.text and payload in final.text) or 500 == response.status_code:			
			print("POSSIBLE XSS ATTACK with payload:", key, ":", injection[key])
			found += 1

	return found
# function for checking the mutated xss payloads
def mutate_xss(endpoint, payloads, r, key, data, url):
	injection = endpoint[data].copy()
	found = 0
	# get the source code from the page before trying any xss, to check your result
	initial = r.get(url)

	# change the number for different number of payloads used (max number should be len(payloads)).
	# comment this and uncomment the following for loop, if we want to use all the payloads
	for payload in random.sample(payloads, 20):
	#for payload in payloads:
		boolean = True
		# first check if the static payload is succesful
		injection[key] = payload
		response = r.request(endpoint["method"],url, data = injection)
		final = r.get(url)

		if (initial.text != response.text and payload in response.text) or (final.text != initial.text and payload in final.text):			
			print("POSSIBLE XSS ATTACK with payload:", key, ":", injection[key])
			found += 1
			boolean = False
		
		# if it is not succesful, mutate it until it is or until the max amount of mutations is reached
		i = 0
		while boolean and i < 10:			
			injection[key] = mutate(payload, i%3)
			i += 1
			response = r.request(endpoint["method"],url, data = injection)
			final = r.get(url)

			if (initial.text != response.text and payload in response.text) or (final.text != initial.text and payload in final.text):						
				print("POSSIBLE XSS ATTACK with payload:", key, ":", injection[key])
				found += 1
				boolean = False

	return found

# function to mutate the payload
# different types of mutation are used
def mutate(s,n):
	# randomly shuffle the characters
	if 0 == n:
		mutated =  ''.join(random.sample(s,len(s)))
	# randomly capitalise characters
	elif 1 == n:	
		mutated = ''.join(random.choice((str.upper, str.lower))(c) for c in s)
	# add random characters in random positions
	elif 2 == n:
		mutated = s
		for times in range(random.randint(1,10)):
			c = chr(random.randint(32,126))
			i = random.randint(1,len(mutated)-1)
			mutated = mutated[:i] + c + mutated[i:]
	return mutated


def main():
	# load the static payloads for SQLi
	with open("sql_payloads.txt") as f:
		sql_payloads = list(set(f.read().splitlines()))
	# load the static payloads for XSS
	with open("xss_payloads.txt") as f:
		xss_payloads = list(set(f.read().splitlines()))

	config = FuzzConfig()
	# load the login endpoint
	url = config.app_root_url
	print("*** URL of the application to check:",url,"***")
	login = config.login_endpoint
	login_url = url+login["url"]
	with requests.Session() as req:
		for endpoint in config.endpoints:
			endpoint_url = url + endpoint["url"]

			print("~~~~~~~~NEW ENDPOINT~~~~~~~~")
			print("-Url:",endpoint["url"])
			
			if endpoint["require_login"]:
				login_request = req.post(login_url, data = login["param_data"])
			# this list should be adapted to our endpoints
			params = ["param_data", "cookie_data"]
			for param in params:
				for key in endpoint[param]:
					if key != "_method":
						print("-Parameter checked:", key)
						value = endpoint[param][key][0].value
						if value == 1:
							print("SQLi testing using static payloads:")
							count = static_sql(endpoint, sql_payloads, req, key, param, endpoint_url)
						elif value == 2:
							print("XSS testing using static payloads:")
							count =	static_xss(endpoint, xss_payloads, req, key, param, endpoint_url)
						elif value == 3:
							print("XSS testing using mutated payloads:")
							count = mutate_xss(endpoint, xss_payloads, req, key, param, endpoint_url)
						elif value == 4:
							print("SQLi testing using mutated payloads:")
							count = mutate_sql(endpoint, sql_payloads, req, key, param, endpoint_url)
						if 0 == count:
							print("No possible attack found.")
						print("")
	
if __name__ == "__main__":
	main()



