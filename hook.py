# -*- coding:utf-8 -*-

#from __future__ import print_function
import frida
import sys
import signal
import requests
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser
import multiprocessing 
import urllib

BURP_HOST="127.0.0.1"
BURP_PORT=8080
SERVER_HOST="127.0.0.1"
SERVER_PORT=17042
SERVER_PROCESS=None

class FridaProxy(BaseHTTPRequestHandler):

  	def do_FRIDA(self):
		request_headers = self.headers
		content_length = request_headers.getheaders('content-length')
		length = int(content_length[0]) if content_length else 0
		self.send_response(200)
		self.end_headers()
		self.wfile.write(self.rfile.read(length))

#device = frida.get_usb_device()
device=frida.get_device_manager().add_remote_device('127.0.0.1:27042')

pid=device._pid_of(u'xxxxBank')

session = device.attach(pid)

print("[OK] Process pid [%d] attached ! " %pid)

script = session.create_script(open('app.js').read())

def start():
		print("[OK] Frida proxy server on ::%d started !" %SERVER_PORT)
		server = HTTPServer(('', SERVER_PORT), FridaProxy)
		server.serve_forever()

def handler(signal_num,frame):        
    global SERVER_PROCESS

    SERVER_PROCESS.terminate()
    sys.exit(signal_num)

def frida_process_message(message,data):

	if message != None:

		#print message
		postdata= (message['payload']['payload'])
		api=(message['payload']['api'])

		if message['payload']['type'] == 'frida':
			req = requests.request('FRIDA', 'http://%s:%d/%s' % (SERVER_HOST, SERVER_PORT,api),data=postdata,proxies={'http':'http://%s:%d' % (BURP_HOST, BURP_PORT)})
			
			script.post({ 'type': 'burp', 'data': urllib.unquote(req.content) })

signal.signal(signal.SIGINT, handler)

script.on('message', frida_process_message)

script.load()

SERVER_PROCESS = multiprocessing.Process(target=start) 

SERVER_PROCESS.start()

try:
  sys.stdin.read()
except KeyboardInterrupt:
  pass