#!/usr/bin/env python

'''
simple_client.py:
Simple Client Socket using the TLS 1.3 Protocol
'''

import socket
import tls_application
import tls_constants

def client_socket():
	s = socket.socket()
	host = socket.gethostname()
	#host = '18.216.1.168'
	port = 1189
	s.connect((host, port))
	client = tls_application.TLSConnection(tls_constants.CLIENT_FLAG)
	tls_client_hello = client.begin_tls_handshake()
	s.send(tls_client_hello)
	server_messages = s.recv(2048)
	client_messages = client.finish_tls_handshake_client(server_messages)
	s.send(client_messages)
	client_enc_message = client.send_enc_message("challenge".encode())
	s.send(client_enc_message)
	server_enc_message = s.recv(1024)
	ptxt_message = client.recv_enc_message(server_enc_message)
	print(ptxt_message.decode('utf-8'))
	s.close()

client_socket()