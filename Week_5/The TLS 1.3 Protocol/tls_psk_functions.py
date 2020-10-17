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
        nonce_length = len(ticket_nonce)
        nonce_length = nonce_length.to_bytes(1,'big')

        HKDF = tls_crypto.HKDF(self.csuite)
        length = HKDF.hash_length
        context = 'resumption'.encode()
        label = tls_crypto.tls_hkdf_label(context, ticket_nonce, length)
        PSK = HKDF.tls_hkdf_expand(resumption_secret, label, length)

        ptxt = PSK + ticket_age_add + ticket_lifetime + self.csuite.to_bytes(2,'big')

        chacha = ChaCha20_Poly1305.new(key = server_static_enc_key, nonce = ticket_nonce)
        ctxt,tag = chacha.encrypt_and_digest(ptxt)
        ticket = ticket_nonce + ctxt + tag
        ticket_length = len(ticket)
        ticket_length = ticket_length.to_bytes(2,'big')

        

        max_early_data_size = 2**12
        extension = max_early_data_size.to_bytes(4, 'big')
        extension_length = len(extension).to_bytes(4,'big')

        new_session_ticket = ticket_lifetime + ticket_age_add + nonce_length + ticket_nonce + ticket_length + ticket + extension_length + extension
        new_session_ticket = self.attach_handshake_header(tls_constants.NEWST_TYPE, new_session_ticket)
        return new_session_ticket


    def tls_13_client_parse_new_session_ticket(self, resumption_secret, nst_msg):
        PSK_dict = {}
        curr_pos = 0
        nst_msg = self.process_handshake_header(tls_constants.NEWST_TYPE,nst_msg)
        

        message_length = len(nst_msg)

        ticket_lifetime = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        curr_pos += 4

        ticket_add = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        curr_pos += 4

        nonce_length = nst_msg[curr_pos : curr_pos + 1]
        curr_pos += 1
        ticket_nonce = nst_msg[curr_pos : curr_pos + 8]
        curr_pos += 8

        
        

        ticket_length = int.from_bytes(nst_msg[curr_pos : curr_pos + 2], 'big')
        curr_pos += 2

        ticket = nst_msg[curr_pos : curr_pos + ticket_length]
        nonce = ticket[:8]
        HKDF = tls_crypto.HKDF(self.csuite)
        length = HKDF.hash_length
        context = 'resumption'.encode()
        label = tls_crypto.tls_hkdf_label(context, ticket_nonce, length)
        PSK = HKDF.tls_hkdf_expand(resumption_secret, label, length)






        curr_pos += ticket_length
        extension_length = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        curr_pos += 4
        max_data = int.from_bytes(nst_msg[curr_pos : curr_pos + 4], 'big')
        
        binder_key_script = "res binder".encode()
        early_secret = HKDF.tls_hkdf_extract(PSK, None)
        binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, binder_key_script, "".encode())

        PSK_dict["PSK"] = PSK
        PSK_dict['lifetime'] = ticket_lifetime
        PSK_dict['lifetime_add'] = ticket_add
        PSK_dict['ticket'] = ticket
        PSK_dict['max_data'] = max_data
        PSK_dict['binder key'] = binder_key
        PSK_dict['csuite'] = self.csuite

        return PSK_dict

    def tls_13_client_prep_psk_mode_extension(self, modes):
        
        PsyKeyExchangeModes = bytes()
        for mode in modes:
            PsyKeyExchangeModes += mode.to_bytes(1, 'big')
        length = len(PsyKeyExchangeModes).to_bytes(1, 'big')
        PsyKeyExchangeModes = tls_constants.PSK_KEX_MODE_TYPE.to_bytes(2, 'big') + length + PsyKeyExchangeModes
        return PsyKeyExchangeModes
        # raise NotImplementedError()

    def tls_13_client_prep_psk_extension(self, PSKS, ticket_age, transcript):
        identities = bytes()
        binder_keys = bytes()
        binders_length = 0

        for index in range(len(PSKS)):
            PSK = PSKS[index]
            current_ticket_age = int(ticket_age[index] / 1000)
            identity = PSK['ticket']
            lifetime = PSK['lifetime']
            lifetime_add = PSK['lifetime_add']
            obfuscated_ticket_age = (ticket_age[index] + lifetime_add) % (2**32)
            # If this is grater than lifetime, then ignore this PSK
            if current_ticket_age > lifetime:
                continue
            csuite = PSK['csuite']

            id_length = len(identity).to_bytes(2,'big')
            psk_identity = id_length + identity + obfuscated_ticket_age.to_bytes(4, 'big')
            identities += psk_identity
            
            if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                hash=SHA256.new()
            if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
                hash=SHA384.new()
            
            binders_length += hash.digest_size + 1
  
        identities_length = len(identities)
        extension_length = 2 + identities_length + 2 + binders_length

        extension_length = extension_length.to_bytes(2,'big')
        identities_length = identities_length.to_bytes(2,'big')
        extension_type = tls_constants.PSK_TYPE.to_bytes(2,'big')


        partial_transcript = transcript + extension_type + extension_length + identities_length + identities 
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, partial_transcript)
        for index in range(len(PSKS)):
            PSK = PSKS[index]
            current_ticket_age = int(ticket_age[index] / 1000)
            lifetime = PSK['lifetime']
            # If this is grater than lifetime, then ignore this PSK
            if current_ticket_age > lifetime:
                continue
            
            binder_key = PSK['binder key']
            csuite = PSK['csuite']
            

            binder_values = tls_crypto.tls_finished_mac(csuite, binder_key, transcript_hash)
            bin_len = len(binder_values).to_bytes(1,'big')
            binder_keys += (bin_len + binder_values)
        
        binders_length = binders_length.to_bytes(2,'big')
        
        offered_psks = identities_length + identities + binders_length + binder_keys
        
        extension_length = len(offered_psks).to_bytes(2, 'big')
        extension = extension_type  + extension_length +  offered_psks
        return extension
        




        #raise NotImplementedError()

    def tls_13_server_parse_psk_extension(self, server_static_enc_key, psk_extension, transcript):
        curr_pos = 0

        extension_type = psk_extension[curr_pos : curr_pos + 2]
        curr_pos += 2

        extension_length = psk_extension[curr_pos : curr_pos + 2]
        curr_pos += 2

        offered_psks = psk_extension[curr_pos:]

        curr_pos_in = 0
        identities_length_byte = offered_psks[curr_pos_in : curr_pos_in + 2]
        identities_length = int.from_bytes(identities_length_byte, 'big')
        curr_pos_in += 2


        #Parse Identities = ticket
        identities_list = []
        id_triples_list = []
        identities = offered_psks[curr_pos_in : curr_pos_in + identities_length]
        curr_pos_in += identities_length


        identity_index = 0
        while (identity_index < len(identities)):
            #something
            identity_length_byte = identities[identity_index : identity_index + 2]
            identity_length = int.from_bytes(identity_length_byte, 'big')
            identity_index += 2

            identity = identities[identity_index : identity_index + identity_length]
            identity_index += identity_length

            obfuscated_ticket_age_byte = identities[identity_index : identity_index + 4]
            obfuscated_ticket_age = int.from_bytes(obfuscated_ticket_age_byte, 'big')
            identity_index += 4

            id_triples = (identity_length, identity, obfuscated_ticket_age)

            identities_list.append(identity_length_byte + identity + obfuscated_ticket_age_byte)

            id_triples_list.append(id_triples)


        ticket_info_list = []
        for index in range(len(id_triples_list)):
            ticket_position = 0
            id_triples = id_triples_list[index]
            ticket = id_triples[1]
            obfuscated_ticket_age = int(id_triples[2] / 1000)

            ticket_nonce = ticket[:8]
            chacha = ChaCha20_Poly1305.new(key = server_static_enc_key, nonce = ticket_nonce)
            # ticket = ticket_nonce + ctxt + tag
            # ptxt = PSK + ticket_age_add + ticket_lifetime + self.csuite.to_bytes(2,'big')
            # ctxt_and_tag = ticket[8:]
            tag_length = 16
            ticket_length = len(ticket)
            ctxt_length = ticket_length - tag_length
            ctxt_range = 8 + ctxt_length
            ctxt = ticket[8 : ctxt_range]
            ptxt = chacha.decrypt(ctxt)

            HKDF = tls_crypto.HKDF(self.csuite)
            length = HKDF.hash_length

            PSK = ptxt[ticket_position : ticket_position + length]
            ticket_position += length

            ticket_age_add_byte = ptxt[ticket_position : ticket_position + 4]
            ticket_position += 4
            ticket_age_add = int.from_bytes(ticket_age_add_byte, 'big')

            ticket_lifetime_byte = ptxt[ticket_position : ticket_position + 4]
            ticket_position += 4
            ticket_lifetime = int.from_bytes(ticket_lifetime_byte, 'big')


            binder_key_script = "res binder".encode()
            early_secret = HKDF.tls_hkdf_extract(PSK, None)
            binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, binder_key_script, "".encode())

            expired = False

            if obfuscated_ticket_age > ticket_lifetime:
                expired = True
            

            csuite_byte = ptxt[ticket_position : ticket_position + 2]
            csuite = int.from_bytes(csuite_byte, 'big')
            ticket_position += 2

            results = (csuite, expired, binder_key, PSK)
            ticket_info_list.append(results)

        
        #Parse binder_keys

        binders_length = int.from_bytes(offered_psks[curr_pos_in : curr_pos_in + 2], 'big')
        curr_pos_in += 2
        binder_values = offered_psks[curr_pos_in:]

        binder_index = 0
        binders_list = []
        while (binder_index < binders_length):
            binder_length = int.from_bytes(binder_values[binder_index : binder_index + 1], 'big')
            binder_index += 1

            binder_value = binder_values[binder_index : binder_index + binder_length]
            binder_index += binder_length

            binder_tuple = (binder_length, binder_value)
            binders_list.append(binder_tuple)
        
        #Decrypt & verify
        partial_transcript = transcript + extension_type + extension_length + identities_length_byte + identities
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, partial_transcript)

        result_list = []
        for index in range(len(binders_list)):
            binder_tuple = binders_list[index]
            binder_value = binder_tuple[1]

            ticket_info_tuple = ticket_info_list[index]
            csuite = ticket_info_tuple[0]
            is_expired = ticket_info_tuple[1]
            binder_key = ticket_info_tuple[2]
            PSK = ticket_info_tuple[3]

            #if is_expired:
            #    continue

            self_binder_value = tls_crypto.tls_finished_mac(csuite, binder_key, transcript_hash)
            current_identity = identities_list[index]
            result_tuples = (PSK, index)

            if self_binder_value == binder_value:
                return result_tuples
        

        raise DecryptError()



    def tls_13_psk_key_schedule(self, psk_secret, dhe_secret, transcript_one, transcript_two, transcript_three, transcript_four):
        # transcript_one = ClientHello
        # transcript_two = ClientHello..ServerHello
        # transcript_three = ClientHello..ServerFinished
        # transcript_four = ClientHello..ClientFinished


        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, binder_key_script, "".encode())

        client_early_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, binder_key, "c e traffic".encode(), transcript_one)
        client_early_key, client_early_iv = tls_crypto.tls_derive_key_iv(self.csuite, client_early_traffic_secret)

        early_exported_master_secret = tls_crypto.tls_derive_secret(self.csuite, early_secret, "e exp master".encode(), transcript_one)
        
        derived_early_secret = tls_crypto.tls_derive_secret(self.csuite, early_exported_master_secret, "derived".encode(), "".encode())

        handshake_secret = tls_crypto.tls_extract_secret(self.csuite, dhe_secret, derived_early_secret)

        client_handshake_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "c hs traffic".encode(), transcript_two)
        client_handshake_key, client_handshake_iv = tls_crypto.tls_derive_key_iv(self.csuite, client_handshake_traffic_secret)

        server_handshake_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "s hs traffic".encode(), transcript_two)
        server_handshake_key, server_handshake_key_iv = tls_crypto.tls_derive_key_iv(self.csuite, server_handshake_traffic_secret)

        derived_handshake_secret = tls_crypto.tls_derive_secret(self.csuite, handshake_secret, "derived".encode(), "".encode())

        master_secret = tls_crypto.tls_extract_secret(self.csuite, None, derived_handshake_secret)

        client_application_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, master_secret, "c ap traffic".encode(), transcript_three)
        client_application_key, client_application_iv = tls_crypto.tls_derive_key_iv(self.csuite, client_application_traffic_secret)
        
        server_application_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, master_secret, "s ap traffic".encode(), transcript_three)
        server_application_key, server_application_iv = tls_crypto.tls_derive_key_iv(self.csuite, server_application_traffic_secret)

        exporter_master_secret = tls_crypto.tls_derive_secret(self.csuite, master_secret, "exp master".encode(), transcript_three)
        resumption_master_secret = tls_crypto.tls_derive_secret(self.csuite, master_secret, "res master".encode(), transcript_four)

        return (early_secret, binder_key, client_early_traffic_secret, client_early_key, client_early_iv, early_exported_master_secret, derived_early_secret, handshake_secret, client_handshake_traffic_secret, client_handshake_key, client_application_iv,
        server_handshake_traffic_secret, server_handshake_key, server_handshake_key_iv, derived_handshake_secret, master_secret, client_application_traffic_secret, client_application_key, client_application_iv, 
        server_application_traffic_secret, server_application_key, server_application_iv, exporter_master_secret, resumption_master_secret)
        # raise NotImplementedError()