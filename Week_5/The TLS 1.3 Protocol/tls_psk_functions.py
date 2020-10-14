#!/usr/bin/env python

'''
tls_psk_functions.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions

PSK_KE_MODE = 0
PSK_DHE_KE_MODE = 1
PRESHARED_KEY_TYPE = 41
EARLY_DATA_TYPE = 42
PRESHARED_KEY_TYPE = 45

class DecryptError(Error):
    pass

class PSKFunctions:
    "This is the class for aspects of the handshake protocol"

    def __init__(self, csuites, extensions, psks, role):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.neg_group = None
        self.neg_version = None
        self.remote_hs_traffic_secret = None
        self.local_hs_traffic_secret = None
        self.transcript = "".encode()
        self.psks = PSKFunctions
        self.csuite = None


    def attach_handshake_header(self, msg_type, msg):
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg


    def process_handshake_header(self, msg_type, msg):
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if (curr_msg_type != msg_type):
            raise InvalidMessageStructureError
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if (msg_len != len(ptxt_msg)):
            raise InvalidMessageStructureError
        return ptxt_msg


    def tls_13_server_new_session_ticket(self, server_static_enc_key, resumption_secret):
        ticket_lifetime = 604800
        ticket_lifetime = ticket_lifetime.to_bytes(4, 'big')
        ticket_age_add = get_random_bytes(4)
        ticket_nonce = get_random_bytes(8)
        HKDF = tls_crypto.HKDF(self.csuite)
        length = HKDF.hash_length

        context = 'resumption'.encode()

        label = tls_crypto.tls_hkdf_label(context, ticket_nonce, length)

        PSK = HKDF.tls_hkdf_expand(resumption_secret, label, length)
        ptxt = PSK + ticket_age_add + ticket_lifetime + self.csuite.to_bytes(2,'big')

        # What is ad??
        chacha = ChaCha20_Poly1305.new(key = server_static_enc_key, nonce = ticket_nonce)
        ctxt,tag = chacha.encrypt_and_digest(ptxt)

        ticket = ticket_nonce + ctxt + tag

        

        max_early_data_size = 2**12
        extension = max_early_data_size.to_bytes(4, 'big')

        new_session_ticket = ticket_lifetime + ticket_age_add +  ticket + extension
        return new_session_ticket
        #raise NotImplementedError()


    def tls_13_client_parse_new_session_ticket(self, resumption_secret, nst_msg):
        PSK_dict = {}
        curr_pos = 0

        

        message_length = len(nst_msg)

        ticket_lifetime = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        curr_pos += 4

        ticket_add = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        curr_pos += 4

        # ticket_nonce = nst_msg[curr_pos : curr_pos + 8]
        # curr_pos += 8

        ticket_length = message_length - 12

        HKDF = tls_crypto.HKDF(self.csuite)
        length = HKDF.hash_length
        ticket = nst_msg[curr_pos : curr_pos + ticket_length]
        PSK = ticket[:length]

        curr_pos += ticket_length
        max_data = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')

        binder_key = "res binder"

        PSK_dict["PSK"] = PSK
        PSK_dict['lifetime'] = ticket_lifetime
        PSK_dict['lifetime_add'] = ticket_lifetime
        PSK_dict['ticket'] = ticket
        PSK_dict['max_data'] = max_data
        PSK_dict['binder key'] = binder_key
        PSK_dict['csuite'] = self.csuite

        return PSK_dict

    def tls_13_client_prep_psk_mode_extension(self, modes):
        
        PsyKeyExchangeModes = bytes()
        for mode in modes:
            PsyKeyExchangeModes += mode.to_bytes(2, 'big')
        length = len(PsyKeyExchangeModes).to_bytes(2, 'big')
        PsyKeyExchangeModes += length
        return PsyKeyExchangeModes
        # raise NotImplementedError()

    def tls_13_client_prep_psk_extension(self, PSKS, ticket_age, transcript):
        raise NotImplementedError()

    def tls_13_server_parse_psk_extension(self, server_static_enc_key, psk_extension, transcript):
        raise NotImplementedError()

    def tls_13_psk_key_schedule(self, psk_secret, dhe_secret, transcript_one, transcript_two, transcript_three, transcript_four):
        raise NotImplementedError()