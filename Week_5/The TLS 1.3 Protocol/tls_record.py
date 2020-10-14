#!/usr/bin/env python

'''
tls_record.py:
Implementation of the TLS 1.3 Record Layer Protocol
'''

from tls_crypto import tls_aead_encrypt, tls_aead_decrypt, tls_nonce
import tls_constants
from tls_error import *

def add_padding(ptxt, csuite):
	if (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
		pad_ptxt = ptxt
	else:
		pad_len = tls_constants.AES_BLOCK_LEN - (len(ptxt) % 16)
		if (pad_len == 0):
			pad_len = tls_constants.AES_BLOCK_LEN
		pad = b'\0' * (pad_len -1)
		last_byte = pad_len.to_bytes(1,'big')
		pad = pad + last_byte
		pad_ptxt = ptxt + pad
	return pad_ptxt

class PlaintextRecordLayer:
	'This is the class for the nonprotected record layer'

	def __init__(self, type_int):
		self.type = type_int
	
	def create_ptxt_packet(self, ptxt):
		ptxt_len = len(ptxt)
		type_bytes = self.type.to_bytes(1, 'big')
		legacy_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
		len_bytes = ptxt_len.to_bytes(2, 'big')
		tls_ptxt = type_bytes + legacy_bytes + len_bytes + ptxt
		return tls_ptxt

	def create_ccs_packet(self):
		type_bytes = tls_constants.CHANGE_TYPE.to_bytes(1, 'big')
		legacy_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
		ptxt_len = 1
		len_bytes = ptxt_len.to_bytes(2, 'big')
		payload_bytes = ptxt_len.to_bytes(1, 'big')
		ccs_ptxt = type_bytes + legacy_bytes + len_bytes + payload_bytes
		return ccs_ptxt 

	def read_ptxt_packet(self, ptxt):
		msg_type = ptxt[0]
		version = ptxt[1:3]
		ptxt_len = ptxt[3:5]
		ptxt_bytes = ptxt[5:]
		p_len = int.from_bytes(ptxt_len, 'big')
		if (p_len != len(ptxt_bytes)):
			raise WrongLengthError()
		if (version != tls_constants.LEGACY_VERSION.to_bytes(2, 'big')):
			raise WrongVersionError()
		return ptxt_bytes

class ProtectedRecordLayer:
	'This is the encrypted record layer'

	def __init__(self, key, iv, type, csuite, role):
		self.type = type
		self.role = role
		if (self.role == tls_constants.RECORD_WRITE):
			self.write_key = key
			self.write_iv = iv
		if (self.role == tls_constants.RECORD_READ):
			self.read_key = key
			self.read_iv = iv
		self.ciphersuite = csuite
		self.sqn_no = 0

	def enc_packet(self, ptxt):
		ptxt_prep = PlaintextRecordLayer(self.type)
		ptxt_msg = ptxt_prep.create_ptxt_packet(ptxt)
		tls_inner_ptxt = add_padding(ptxt_msg, self.ciphersuite)
		ptxt_type_bytes = self.type.to_bytes(1,'big')
		legacy_type_bytes = tls_constants.APPLICATION_TYPE.to_bytes(1,'big')
		legacy_vers_bytes = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
		nonce = tls_nonce(self.ciphersuite, self.sqn_no, self.write_iv)
		len_ctxt = len(ptxt) + tls_constants.MAC_LEN[self.ciphersuite]
		len_bytes = len_ctxt.to_bytes(2, 'big')
		header = legacy_type_bytes + legacy_vers_bytes + len_bytes
		ctxt = tls_aead_encrypt(self.ciphersuite, self.write_key, nonce, ptxt)
		tls_record = header + ctxt
		self.sqn_no = self.sqn_no + 1
		return tls_record
		
	def dec_packet(self, tls_record):
		nonce = tls_nonce(self.ciphersuite, self.sqn_no, self.read_iv)
		header = tls_record[:5]
		len_ctxt = int.from_bytes(header[3:5], 'big')
		ciphertext = tls_record[5:5+len_ctxt]
		plaintext = tls_aead_decrypt(self.ciphersuite, self.read_key, nonce, ciphertext)
		self.sqn_no = self.sqn_no + 1
		return plaintext