#!/usr/bin/env python

'''
simple_server.py:
Simple Server Socket using the TLS 1.3 Protocol
'''

import sys
import traceback
import socket
import tls_application
import tls_constants

def server_socket():
	s_socket = socket.socket()
	host = socket.gethostname()
	port = 1189
	# The next setting allows us to reuse the port if still bound
	# By a previous run of the server
	s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s_socket.bind((host, port))
	s_socket.listen(5)
	while True:
		try:
			c_socket, addr = s_socket.accept()
			print('Got connection from', addr)
			server = tls_application.TLSConnection(tls_constants.SERVER_FLAG)
			tls_client_hello = c_socket.recv(1024)
			server_messages = server.wait_for_tls_connection(tls_client_hello)
			c_socket.send(server_messages)
			client_messages = c_socket.recv(1024)
			server.finish_tls_connection_server(client_messages)
			client_enc_message = c_socket.recv(1024)
			ptxt_message = server.recv_enc_message(client_enc_message)
			print(ptxt_message.decode('utf-8'))
			server_enc_message = server.send_enc_message("response".encode())
			c_socket.send(server_enc_message)
			c_socket.close()
		except KeyboardInterrupt:
			print("Shutting Server Down...")
			try:
				c_socket.close()
			except UnboundLocalError:
				print("Did not establish client connection.")
			s_socket.close()
			sys.exit()
		except Exception as e: 
			print(e)
			traceback.print_exc()
			print("Something went wrong!")
			try:
				c_socket.close()
			except UnboundLocalError:
				print("Did not establish client connection.")
			s_socket.close()
			server_socket()

server_socket()