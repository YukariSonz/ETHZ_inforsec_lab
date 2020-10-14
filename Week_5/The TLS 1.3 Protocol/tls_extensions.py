#!/usr/bin/env python

'''
tls_extensions.py:
Contains the functions needed to create extensions throughout the handshake protocol
'''

import tls_constants
import tls_crypto
from tls_error import *

### SUPPORTED VERSION PREPARATION FOR CLIENTHELLO
def prep_support_vers_ext(extensions):
	ext_type = tls_constants.SUPPORT_VERS_TYPE.to_bytes(2, 'big')
	supported_versions = extensions[tls_constants.SUPPORT_VERS_TYPE]
	num_versions = len(supported_versions)
	supp_vers_bytes = "".encode()
	for i in range(num_versions):
		supp_vers_bytes = supp_vers_bytes + supported_versions[i].to_bytes(2, 'big')
	len_vers_bytes = len(supp_vers_bytes).to_bytes(1, 'big')
	len_msg = len(len_vers_bytes + supp_vers_bytes).to_bytes(2, 'big')
	supp_vers_ext = ext_type + len_msg + len_vers_bytes + supp_vers_bytes
	return supp_vers_ext

### SUPPORTED GROUP PREPERATION FOR CLIENTHELLO
def prep_support_groups_ext(extensions):
	ext_type = tls_constants.SUPPORT_GROUPS_TYPE.to_bytes(2, 'big')
	supported_groups = extensions[tls_constants.SUPPORT_GROUPS_TYPE]
	num_groups = len(supported_groups)
	supp_groups_bytes = "".encode()
	for i in range(num_groups):
		supp_groups_bytes = supp_groups_bytes + supported_groups[i].to_bytes(2, 'big')
	len_list_bytes = len(supp_groups_bytes).to_bytes(2, 'big')
	len_groups_bytes = (len(supp_groups_bytes)+2).to_bytes(2, 'big')
	supp_groups_ext = ext_type + len_groups_bytes + len_list_bytes + supp_groups_bytes
	return supp_groups_ext

### SUPPORTED VERSION NEGOTIATION FOR SERVERHELLO
def negotiate_support_vers_ext(extensions, supp_remote_vers):
	len_vers = supp_remote_vers[0]
	supp_remote_vers = supp_remote_vers[1:]
	num_remote_vers = len_vers // 2
	supp_local_vers = extensions[tls_constants.SUPPORT_VERS_TYPE]
	num_local_vers = len(supp_local_vers)
	for i in range(num_local_vers):
		for j in range(num_remote_vers):
			curr_remote_vers = int.from_bytes(supp_remote_vers[2*j:2*(j+1)], 'big')
			if (supp_local_vers[i] == curr_remote_vers):
				return supp_local_vers[i]
	raise NoCommonVersionError()

### SUPPORTED VERSION OUTPUT FOR SERVERHELLO
def finish_support_vers_ext(neg_vers):
	ext_type = tls_constants.SUPPORT_VERS_TYPE.to_bytes(2, 'big')
	neg_vers_bytes = neg_vers.to_bytes(2, 'big')
	len_vers_bytes = len(neg_vers_bytes).to_bytes(2, 'big')
	neg_vers_ext = ext_type + len_vers_bytes + neg_vers_bytes
	return neg_vers_ext

### SUPPORTED GROUP NEGOTIATION FOR SERVERHELLO
def negotiate_support_group_ext(extensions, neg_group, num_remote_group, supp_remote_group):
	supp_remote_group = supp_remote_group[2:]
	num_remote_group = num_remote_group - 1
	supp_local_group = extensions[tls_constants.SUPPORT_GROUPS_TYPE]
	num_local_group = len(supp_local_group)
	for i in range(num_local_group):
		for j in range(num_remote_group):
			curr_remote_group = int.from_bytes(supp_remote_group[2*j:2*(j+1)], 'big')
			if (supp_local_group[i] == curr_remote_group):
				neg_group = supp_local_group[i]
				return supp_local_group[i]
	raise NoCommonGroupError()
	return 0

### SUPPORTED GROUP OUTPUT FOR SERVERHELLO
def finish_support_group_ext(neg_group):
	ext_type = tls_constants.SUPPORT_GROUPS_TYPE.to_bytes(2, 'big')
	neg_group_bytes = neg_group.to_bytes(2, 'big')
	len_group_bytes = len(neg_group_bytes).to_bytes(2, 'big')
	neg_group_ext = ext_type + len_group_bytes + neg_group_bytes
	return neg_group_ext

### SUPPORTED SIGNATURE ALGORITHMS FOR CLIENTHELLO
def prep_signature_ext(extensions):
	ext_type = tls_constants.SIG_ALGS_TYPE.to_bytes(2, 'big')
	supported_sigs = extensions[tls_constants.SIG_ALGS_TYPE]
	num_sigs = len(supported_sigs)
	supp_sigs_bytes = "".encode()
	for i in range(num_sigs):
		supp_sigs_bytes = supp_sigs_bytes + supported_sigs[i].to_bytes(2, 'big')
	len_list_bytes = len(supp_sigs_bytes).to_bytes(2, 'big')
	len_sigs_bytes = (len(supp_sigs_bytes)+2).to_bytes(2, 'big')
	supp_sigs_ext = ext_type + len_sigs_bytes + len_list_bytes + supp_sigs_bytes
	return supp_sigs_ext

def negotiate_signature_ext(extensions, supp_remote_sigs):
	supp_local_sigs = extensions[tls_constants.SIG_ALGS_TYPE]
	len_remote_sigs = int.from_bytes(supp_remote_sigs[:2], 'big')
	num_remote_sigs = len_remote_sigs // 2
	supp_remote_sigs = supp_remote_sigs[2:]
	num_local_sigs = len(supp_local_sigs)
	for i in range(num_local_sigs):
		for j in range(num_remote_sigs):
			curr_remote_sig = int.from_bytes(supp_remote_sigs[2*j:2*(j+1)], 'big')
			if (supp_local_sigs[i] == curr_remote_sig):
				return supp_local_sigs[i]
	raise NoCommonSignatureError

### SUPPORTED KEYSHARE PREPERATION FOR CLIENTHELLO
def prep_keyshare_ext(extensions):
	ext_type = tls_constants.KEY_SHARE_TYPE.to_bytes(2, 'big')
	groups = extensions[tls_constants.SUPPORT_GROUPS_TYPE]
	num_groups = len(groups)
	keyshare_ext_bytes = "".encode()
	ec_sec_keys = {}
	for i in range(num_groups):
		curve = tls_crypto.ec_setup(tls_constants.GROUP_FLAGS[groups[i]])
		(ec_sec_key, ec_pub_key) = tls_crypto.ec_key_gen(curve)
		ec_sec_keys.update({groups[i]:ec_sec_key})
		pub_key_bytes = tls_crypto.convert_ec_pub_bytes(ec_pub_key, groups[i])
		if (groups[i] != tls_constants.SECP256R1_VALUE) and (groups[i] != tls_constants.SECP384R1_VALUE) and (groups[i] != tls_constants.SECP521R1_VALUE):
			legacy_form = "".encode()
		else:
			legacy_form_int = 4
			legacy_form = legacy_form_int.to_bytes(1, 'big')
		pub_key_bytes = legacy_form + pub_key_bytes
		len_pub_key_bytes = len(pub_key_bytes).to_bytes(2, 'big')
		name_group_bytes = groups[i].to_bytes(2, 'big')
		keyshare = name_group_bytes + len_pub_key_bytes + pub_key_bytes
		len_keyshare_bytes = len(keyshare).to_bytes(2, 'big')
		keyshare_ext_bytes = keyshare_ext_bytes + len_keyshare_bytes + keyshare
	len_ext_bytes = len(keyshare_ext_bytes).to_bytes(2, 'big')
	keyshare_ext = ext_type + len_ext_bytes + keyshare_ext_bytes
	return keyshare_ext, ec_sec_keys

def negotiate_keyshare_ext(extensions, neg_group, ext_len, remote_keyshare_bytes):
	curr_pos = 0
	keyshare_ext_bytes = "".encode()
	while (curr_pos < ext_len):
		len_keyshare = int.from_bytes(remote_keyshare_bytes[curr_pos:curr_pos+2], 'big')
		curr_pos = curr_pos + 2
		curr_name = int.from_bytes(remote_keyshare_bytes[curr_pos:curr_pos+2], 'big')
		curr_pos = curr_pos + 2
		pub_key_len = int.from_bytes(remote_keyshare_bytes[curr_pos:curr_pos+2], 'big')
		curr_pos = curr_pos + 2
		ext_bytes = remote_keyshare_bytes[curr_pos:curr_pos+pub_key_len]
		if (curr_name == tls_constants.SECP256R1_VALUE) or (curr_name == tls_constants.SECP384R1_VALUE) or (curr_name == tls_constants.SECP521R1_VALUE):
			ext_bytes = ext_bytes[1:]
		supported_groups = extensions[tls_constants.SUPPORT_GROUPS_TYPE]
		if (neg_group == curr_name) or ((neg_group == 0) and (curr_name in supported_groups)):
			if (curr_name == tls_constants.SECP256R1_VALUE) or (curr_name == tls_constants.SECP384R1_VALUE) or (curr_name == tls_constants.SECP521R1_VALUE):
				ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(ext_bytes, curr_name)
				curve = tls_crypto.ec_setup(tls_constants.GROUP_FLAGS[curr_name])
				sec_key, pub_key = tls_crypto.ec_key_gen(curve)
				ec_sec_key = sec_key
				neg_group = curr_name
				pub_key_bytes = tls_crypto.convert_ec_pub_bytes(pub_key, curr_name)
				legacy_form_int = 4
				legacy_form = legacy_form_int.to_bytes(1, 'big')
				pub_key_bytes = legacy_form + pub_key_bytes
				len_pub_key_bytes = len(pub_key_bytes).to_bytes(2, 'big')
				name_group_bytes = curr_name.to_bytes(2, 'big')
				keyshare_ext_bytes = name_group_bytes + len_pub_key_bytes + pub_key_bytes
				len_extension = len(keyshare_ext_bytes).to_bytes(2, 'big')
				ext_type = tls_constants.KEY_SHARE_TYPE.to_bytes(2, 'big')
				keyshare_ext = ext_type + len_extension + keyshare_ext_bytes
				return keyshare_ext, neg_group, ec_pub_key, ec_sec_key
		curr_pos = curr_pos + pub_key_len
	raise NoCommonGroupError()

### NEGOTIATE SHARED CIPHERSUITE FOR SERVER
### NOTE: TECHNICALLY NOT A TLS EXTENSION BUT WE PLACE IT HERE FOR CONSISTENCY OF
### NEGOTIATION FUNCTIONS.
def negotiate_support_csuite(csuites, num_remote_csuites, supp_remote_csuites):
	supp_local_csuites = csuites
	num_local_csuites = len(supp_local_csuites)
	for i in range(num_local_csuites):
		for j in range(num_remote_csuites):
			curr_remote_csuite = int.from_bytes(supp_remote_csuites[2*j:2*(j+1)], 'big')
			if (supp_local_csuites[i] == curr_remote_csuite):
				return supp_local_csuites[i]
	raise NoCommonCiphersuiteError()