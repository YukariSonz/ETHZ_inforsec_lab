#!/usr/bin/env python

'''
tls_application.py:
Implementation of the TLS 1.3 Protocol
'''

import tls_constants
import tls_record
import tls_handshake
from tls_error import *

class TLSConnection:
	'This is the high-level TLS API'

	def __init__(self, role):
		self.role = role

	def begin_tls_handshake(self):
		if (self.role != tls_constants.CLIENT_FLAG):
			raise StateConfusionError()
		self.client_handshake = tls_handshake.Handshake(tls_constants.CLIENT_SUPPORTED_CIPHERSUITES, tls_constants.CLIENT_SUPPORTED_EXTENSIONS, self.role)
		chelo_msg = self.client_handshake.tls_13_client_hello()
		self.client_ptxt_connect = tls_record.PlaintextRecordLayer(tls_constants.HANDSHAKE_TYPE)
		tls_client_hello = self.client_ptxt_connect.create_ptxt_packet(chelo_msg)
		return tls_client_hello

	def wait_for_tls_connection(self, tls_client_hello):
		if (self.role != tls_constants.SERVER_FLAG):
			raise StateConfusionError()
		self.server_ptxt_connect = tls_record.PlaintextRecordLayer(tls_constants.HANDSHAKE_TYPE)
		chelo_msg = self.server_ptxt_connect.read_ptxt_packet(tls_client_hello)
		self.server_handshake = tls_handshake.Handshake(tls_constants.SERVER_SUPPORTED_CIPHERSUITES, tls_constants.SERVER_SUPPORTED_EXTENSIONS, self.role)
		shelo_result = self.server_handshake.tls_13_server_hello(chelo_msg)
		if (shelo_result[0] != 0):
			server_error = tls_record.PlaintextRecordLayer(tls_constants.ALERT_TYPE)
			tls_alert_msg = server_error.create_ptxt_packet(shelo_result[1])
			return tls_alert_msg
		else:
			shelo_msg = shelo_result[1]
		tls_server_hello = self.server_ptxt_connect.create_ptxt_packet(shelo_msg)
		tls_ccs_msg = self.server_ptxt_connect.create_ccs_packet()
		self.local_hs_traffic_key, self.local_hs_traffic_iv, self.csuite = self.server_handshake.tls_13_compute_local_hs_key_iv()
		self.remote_hs_traffic_key, self.remote_hs_traffic_iv, self.csuite = self.server_handshake.tls_13_compute_remote_hs_key_iv()
		self.server_hs_enc_connect = tls_record.ProtectedRecordLayer(self.local_hs_traffic_key, self.local_hs_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_WRITE)
		self.client_hs_enc_connect = tls_record.ProtectedRecordLayer(self.remote_hs_traffic_key, self.remote_hs_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_READ)
		enc_ext_msg = self.server_handshake.tls_13_server_enc_ext()
		tls_enc_ext_msg = self.server_hs_enc_connect.enc_packet(enc_ext_msg)
		scert_msg = self.server_handshake.tls_13_server_cert()
		tls_scert_msg = self.server_hs_enc_connect.enc_packet(scert_msg)
		cert_verify_msg = self.server_handshake.tls_13_server_cert_verify()
		tls_cert_verify_msg = self.server_hs_enc_connect.enc_packet(cert_verify_msg)
		fin_msg = self.server_handshake.tls_13_finished()
		tls_fin_msg = self.server_hs_enc_connect.enc_packet(fin_msg)
		self.local_ap_traffic_key, self.local_ap_traffic_iv, self.csuite = self.server_handshake.tls_13_compute_local_ap_key_iv()
		self.remote_ap_traffic_key, self.remote_ap_traffic_iv, self.csuite = self.server_handshake.tls_13_compute_remote_ap_key_iv()
		self.remote_ap_enc_connect = tls_record.ProtectedRecordLayer(self.remote_ap_traffic_key, self.remote_ap_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_READ)
		self.local_ap_enc_connect = tls_record.ProtectedRecordLayer(self.local_ap_traffic_key, self.local_ap_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_WRITE)
		return tls_server_hello + tls_ccs_msg + tls_enc_ext_msg + tls_scert_msg + tls_cert_verify_msg + tls_fin_msg

	def finish_tls_handshake_client(self, server_messages):
		if (self.role != tls_constants.CLIENT_FLAG):
			raise WrongRoleError()
		total_len = len(server_messages)
		len_processed = 0
		while (len_processed < total_len):
			curr_pos = 0
			msg_type = int.from_bytes(server_messages[:tls_constants.MSG_TYPE_LEN], 'big')
			curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
			legacy_vers_type = int.from_bytes(server_messages[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN], 'big')
			curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
			msg_len = int.from_bytes(server_messages[curr_pos:curr_pos + tls_constants.HEAD_LEN_LEN], 'big')
			curr_pos = curr_pos + tls_constants.HEAD_LEN_LEN
			total_msg_len = curr_pos + msg_len
			curr_msg = server_messages[:total_msg_len]
			server_messages = server_messages[total_msg_len:]
			if (msg_type == tls_constants.ALERT_TYPE):
				msg = self.client_ptxt_connect.read_ptxt_packet(curr_msg)
				tls_read_alert(msg)
			if (msg_type == tls_constants.HANDSHAKE_TYPE):
				msg = self.client_ptxt_connect.read_ptxt_packet(curr_msg)
				self.client_handshake.tls_13_process_server_hello(msg)
				self.remote_hs_traffic_key, self.remote_hs_traffic_iv, self.csuite = self.client_handshake.tls_13_compute_remote_hs_key_iv()
				self.local_hs_traffic_key, self.local_hs_traffic_iv, self.csuite = self.client_handshake.tls_13_compute_local_hs_key_iv()
				self.server_hs_enc_connect = tls_record.ProtectedRecordLayer(self.remote_hs_traffic_key, self.remote_hs_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_READ)
				self.client_hs_enc_connect = tls_record.ProtectedRecordLayer(self.local_hs_traffic_key, self.local_hs_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_WRITE)
			if (msg_type == tls_constants.APPLICATION_TYPE):
				ptxt_msg = self.server_hs_enc_connect.dec_packet(curr_msg)
				msg_type = ptxt_msg[0]
				if (msg_type == tls_constants.ENEXT_TYPE):
					self.client_handshake.tls_13_process_enc_ext(ptxt_msg)
				if (msg_type == tls_constants.CERT_TYPE):
					self.client_handshake.tls_13_process_server_cert(ptxt_msg)
				if (msg_type == tls_constants.CVFY_TYPE):
					self.client_handshake.tls_13_process_server_cert_verify(ptxt_msg)
				if (msg_type == tls_constants.FINI_TYPE):
					self.client_handshake.tls_13_process_finished(ptxt_msg)
			len_processed = len_processed + total_msg_len
		fin_msg = self.client_handshake.tls_13_finished()
		tls_fin_msg = self.client_hs_enc_connect.enc_packet(fin_msg)
		self.remote_ap_traffic_key, self.remote_ap_traffic_iv, self.csuite = self.client_handshake.tls_13_compute_remote_ap_key_iv()
		self.local_ap_traffic_key, self.local_ap_traffic_iv, self.csuite = self.client_handshake.tls_13_compute_local_ap_key_iv()
		self.remote_ap_enc_connect = tls_record.ProtectedRecordLayer(self.remote_ap_traffic_key, self.remote_ap_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_READ)
		self.local_ap_enc_connect = tls_record.ProtectedRecordLayer(self.local_ap_traffic_key, self.local_ap_traffic_iv, tls_constants.APPLICATION_TYPE, self.csuite, tls_constants.RECORD_WRITE)
		return tls_fin_msg

	def finish_tls_connection_server(self, client_messages):
		if (self.role != tls_constants.SERVER_FLAG):
			raise WrongRoleError()
		curr_pos = 0
		curr_msg = client_messages
		msg_type = int.from_bytes(curr_msg[:tls_constants.MSG_TYPE_LEN], 'big')
		curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
		msg_len = int.from_bytes(curr_msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
		if (msg_type == tls_constants.APPLICATION_TYPE):
			ptxt_msg = self.client_hs_enc_connect.dec_packet(curr_msg[:msg_len])
			msg_type = ptxt_msg[0]
			if (msg_type == tls_constants.FINI_TYPE):
				self.server_handshake.tls_13_process_finished(ptxt_msg)

	def send_enc_message(self, plaintext):
		tls_enc_msg = self.local_ap_enc_connect.enc_packet(plaintext)
		return tls_enc_msg

	def recv_enc_message(self, ciphertext):
		ptxt_msg = self.remote_ap_enc_connect.dec_packet(ciphertext)
		return ptxt_msg