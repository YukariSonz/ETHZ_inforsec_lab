#!/usr/bin/env python

'''
tls_extensions.py:
Contains the functions needed to raise errors throughout the TLS protocol
'''

import tls_constants

class Error(Exception):
	"""Base class for exceptions in this implementation"""
	pass

class NoCommonGroupError(Error):
	pass

class NoCommonCiphersuiteError(Error):
	pass

class NoCommonVersionError(Error):
	pass

class NoCommonSignatureError(Error):
	pass

class StateConfusionError(Error):
	pass

class WrongLengthError(Error):
	pass

class VerificationFailure(Error):
	pass

class InvalidMessageStructureError(Error):
	pass

class UnexpectedMessageError(Error):
	pass

class WrongRoleError(Error):
	pass

class WrongVersionError(Error):
	pass

class IllegalParameterError(Exception):
	def __init__(self):
		print("IllegalParameterError: Some Attribute did not verify correctly")
		raise AttributeError

def tls_prepare_alert(type_int):
	alert_level = tls_constants.TLS_ERROR_FATAL_LVL.to_bytes(1, 'big')
	alert_type = type_int.to_bytes(1, 'big')
	alert_msg = alert_level + alert_type
	return alert_msg

def tls_read_alert(alert_msg):
	alert_type = alert_msg[1]
	if (alert_type == tls_constants.TLS_ILLEGAL_PARA):
		print("Server didn't like a parameter!")
		raise IllegalParameterError