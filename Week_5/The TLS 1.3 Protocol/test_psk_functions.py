import unittest
import filecmp
from Crypto.Hash import SHA256, SHA384
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions
from tls_psk_functions import PSKFunctions


SAMPLES = 15


class Tests(unittest.TestCase):

    def test_tls_13_server_new_session_ticket(self):
        server_static_enc_keys = []
        resumption_secrets = []
        csuites = []
        PSKFun= PSKFunctions(None, None, None, None)

        lifetime_adds = []

        with open('ut_tls_13_server_new_session_ticket_byte_inputs', 'rb') as byte_input:
            with open('ut_tls_13_server_new_session_ticket_int_inputs.txt', 'r') as int_input:
                for _ in range(SAMPLES):
                    int_input.readline()
                    inputs_ints = int_input.readline().split()
                    csuite = int(inputs_ints[0])
                    server_static_enc_key_len = int(inputs_ints[1])
                    resumption_secret_len = int(inputs_ints[2])
                    server_static_enc_key = byte_input.read(server_static_enc_key_len)
                    resumption_secret  =byte_input.read(resumption_secret_len)
                    csuites.append(csuite)
                    resumption_secrets.append(resumption_secret)
                    server_static_enc_keys.append(server_static_enc_key)

        for i in range(SAMPLES):
            with self.subTest(sample=i):
                PSKFun.csuite = csuites[i]
                nst_msg = PSKFun.tls_13_server_new_session_ticket(server_static_enc_keys[i], resumption_secrets[i])
                psk_dict = PSKFun.tls_13_client_parse_new_session_ticket(resumption_secrets[i], nst_msg)
                self.assertEqual(psk_dict['lifetime'], 604800)
                lifetime_adds.append(psk_dict['lifetime_add'])
                max_data = psk_dict['max_data']
                self.assertEqual(max_data, 2**12)
                ticket = psk_dict['ticket']
                nonce = ticket[:8]
                ciphertext = ticket[8:]
                cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
                aead_ctxt_len = len(ciphertext)
                mac_len = tls_constants.MAC_LEN[tls_constants.TLS_CHACHA20_POLY1305_SHA256]
                ctxt_len = aead_ctxt_len - mac_len
                ctxt = ciphertext[:ctxt_len]
                tag = ciphertext[ctxt_len:]
                plaintext = cipher.decrypt_and_verify(ctxt, tag)
                psk = plaintext[:len(plaintext)-10]
                ticket_add_age_bytes = plaintext[len(psk):len(psk)+4]
                ticket_lifetime_bytes = plaintext[len(psk)+4:len(psk)+8]
                csuite_bytes = plaintext[len(psk)+8:len(psk)+10]
                self.assertEqual(int.from_bytes(ticket_lifetime_bytes, 'big'), psk_dict['lifetime'])
                self.assertEqual(int.from_bytes(csuite_bytes, 'big'), PSKFun.csuite)


    def test_tls_13_client_parse_new_session_ticket(self):
        pass
        resumption_secrets = []
        csuites = []
        nst_msgs = []
        psk_dicts = []
        psk_dicts_out = []
        PSKFun = PSKFunctions(None, None, None, None)

        with open('ut_tls_13_client_parse_new_session_ticket_byte_inputs', 'rb') as byte_input:
            with open('ut_tls_13_client_parse_new_session_ticket_int_inputs.txt', 'r') as int_input:
                for _ in range(SAMPLES):
                    line_space = int_input.readline()
                    input_ints = int_input.readline().split()
                    csuites.append(int(input_ints[0]))
                    resumption_secret_len = int(input_ints[1])
                    nst_msg_len = int(input_ints[2])
                    resumption_secrets.append(byte_input.read(resumption_secret_len))
                    nst_msgs.append(byte_input.read(nst_msg_len))

        with open('ut_tls_13_client_parse_new_session_ticket_byte_outputs', 'rb') as byte_output:
            with open('ut_tls_13_client_parse_new_session_ticket_int_outputs.txt', 'r') as int_output:
                for _ in range(SAMPLES):
                    line_space = int_output.readline()
                    input_ints = int_output.readline().split()

                    psk_len = int(input_ints[0])
                    psk = byte_output.read(psk_len)

                    ticket_len = int(input_ints[3])
                    ticket = byte_output.read(ticket_len)

                    binder_key_len = int(input_ints[5])
                    binder_key = byte_output.read(binder_key_len)
                    psk_dicts.append(
                        {
                            "PSK": psk,
                            "lifetime": int(input_ints[1]),
                            "lifetime_add": int(input_ints[2]),
                            "ticket": ticket,
                            "max_data": int(input_ints[4]),
                            "binder key": binder_key,
                            "csuite": int(input_ints[6]),
                        })

        for i in range(SAMPLES):
            with self.subTest(sample=i):
                PSKFun.csuite = csuites[i]
                psk_dict = PSKFun.tls_13_client_parse_new_session_ticket(
                    resumption_secrets[i], nst_msgs[i])
                psk_dicts_out.append(psk_dict)
                self.assertDictEqual(psk_dict, psk_dicts[i])

        with open('ut_tls_13_client_parse_new_session_ticket_byte_outputs_temp', 'wb') as byte_output:
            with open('ut_tls_13_client_parse_new_session_ticket_int_outputs_temp.txt', 'w') as int_output:
                for psk_dict in psk_dicts_out:
                    byte_output.write(
                        psk_dict["PSK"] + psk_dict["ticket"] + psk_dict["binder key"])
                    int_output.write(
                        f'\n{len(psk_dict["PSK"])} {psk_dict["lifetime"]} {psk_dict["lifetime_add"]} {len(psk_dict["ticket"])} {psk_dict["max_data"]} {len(psk_dict["binder key"])} {psk_dict["csuite"]}\n')

    def test_tls_13_client_prep_psk_mode_extension(self):
        psk_mode_ext_mult = []
        with open('ut_tls_13_client_prep_psk_mode_extension_int_inputs.txt', 'r') as int_input:
            for _ in range(SAMPLES):
                line_space = int_input.readline()
                input_ints = int_input.readline().split()
                modes = ()
                for i in range(len(input_ints)):
                    modes = modes + (int(input_ints[i]),)
                PSK = PSKFunctions(None,None,None,None)
                ext_bytes = PSK.tls_13_client_prep_psk_mode_extension(modes)
                psk_mode_ext_mult.append(ext_bytes)
        with open('ut_tls_13_client_prep_psk_mode_extension_outputs_temp.txt', 'w') as output:
            for psk_mode_ext in psk_mode_ext_mult:
                output.write('\n%s\n' % (psk_mode_ext.hex()))
        self.assertTrue(filecmp.cmp(
            'ut_tls_13_client_prep_psk_mode_extension_outputs_temp.txt', 'ut_tls_13_client_prep_psk_mode_extension_outputs.txt'))


    def test_tls_13_client_prep_psk_extension(self):
        psk_csuites = []
        psks_list = []
        ticket_age_list = []
        transcripts = []
        psk_extensions = []
        psk_extensions_out = []
        PSKFun = PSKFunctions(None, None, None, None)

        with open('ut_tls_13_client_prep_psk_extension_byte_inputs', 'rb') as byte_input:
            with open('ut_tls_13_client_prep_psk_extension_int_inputs.txt', 'r') as int_input:
                for _ in range(SAMPLES):
                    line_space = int_input.readline()
                    input_ints = int_input.readline().split()
                    csuite = int(input_ints[0])
                    transcript_len = int(input_ints[1])
                    num_psks = int(input_ints[2])
                    transcript = byte_input.read(transcript_len)
                    psks = []
                    ticket_age = []
                    for _ in range(num_psks):

                        input_ints = int_input.readline().split()
                        psk_len = int(input_ints[0])
                        lifetime = int(input_ints[1])
                        lifetime_add = int(input_ints[2])
                        ticket_len = int(input_ints[3])
                        max_data = int(input_ints[4])
                        binder_key_len = int(input_ints[5])
                        psk_csuite = int(input_ints[6])

                        psk = byte_input.read(psk_len)

                        ticket = byte_input.read(ticket_len)

                        binder_key = byte_input.read(binder_key_len)                   
                        psks.append(
                            {
                                "PSK": psk,
                                "lifetime": lifetime,
                                "lifetime_add": lifetime_add,
                                "ticket": ticket,
                                "max_data": max_data,
                                "binder key": binder_key,
                                "csuite": psk_csuite
                            })
                        ticket_age.append(int(input_ints[7]))

                    psk_csuites.append(csuite)
                    psks_list.append(psks)
                    ticket_age_list.append(ticket_age)
                    transcripts.append(transcript)

        with open('ut_tls_13_client_prep_psk_extension_byte_outputs', 'rb') as byte_output:
            with open('ut_tls_13_client_prep_psk_extension_int_outputs.txt', 'r') as int_output:
                for _ in range(SAMPLES):
                    line_space = int_output.readline()
                    psk_extension_len = int(int_output.readline())
                    psk_extension = byte_output.read(psk_extension_len)
                    psk_extensions.append(psk_extension)

        for i in range(SAMPLES):
            with self.subTest(sample=i):
                PSKFun.csuite = psk_csuites[i]
                psk_extension = PSKFun.tls_13_client_prep_psk_extension(
                    psks_list[i], ticket_age_list[i], transcripts[i])
                psk_extensions_out.append(psk_extension)
                self.assertSequenceEqual(psk_extension, psk_extensions[i])

        with open('ut_tls_13_client_prep_psk_extension_byte_outputs_temp', 'wb') as byte_output:
            with open('ut_tls_13_client_prep_psk_extension_int_outputs_temp.txt', 'w') as int_output:
                for psk_extension in psk_extensions_out:
                    byte_output.write(psk_extension)
                    int_output.write(f'\n{len(psk_extension)}\n')

    def test_tls_13_server_parse_psk_extension(self):
        psk_csuites = []
        psk_extensions = []
        transcripts = []
        psks = []
        psks_out = []
        server_static_enc_keys = []
        identities = []
        identities_out = []
        PSK = PSKFunctions(None, None, None, None)
        with open('ut_tls_13_server_parse_psk_extension_byte_inputs', 'rb') as byte_input:
            with open('ut_tls_13_server_parse_psk_extension_int_inputs.txt', 'r') as int_input:
                for _ in range(SAMPLES):
                    int_input.readline()
                    input_ints = int_input.readline().split()
                    csuite = int(input_ints[0])
                    psk_extension_len = int(input_ints[1])
                    transcript_len = int(input_ints[2])
                    server_static_enc_key_len = int(input_ints[3])
                    psk_extension = byte_input.read(psk_extension_len)
                    transcript = byte_input.read(transcript_len)
                    server_static_enc_key = byte_input.read(server_static_enc_key_len)
                    psk_csuites.append(csuite)
                    psk_extensions.append(psk_extension)
                    transcripts.append(transcript)
                    server_static_enc_keys.append(server_static_enc_key)

        with open('ut_tls_13_server_parse_psk_extension_byte_outputs', 'rb') as byte_output:
            with open('ut_tls_13_server_parse_psk_extension_int_outputs.txt', 'r') as int_output:
                for _ in range(SAMPLES):
                    int_output.readline()
                    input_ints = int_output.readline().split()
                    psk_len = int(input_ints[0])
                    selected_identity = int(input_ints[1])
                    psk = byte_output.read(psk_len)
                    psks.append(psk)
                    identities.append(selected_identity)

        for i in range(SAMPLES):
            with self.subTest(sample=i):
                PSK.csuite = psk_csuites[i]
                psk, selected_identity = PSK.tls_13_server_parse_psk_extension(
                    server_static_enc_keys[i], psk_extensions[i], transcripts[i])
                psks_out.append(psk)
                identities_out.append(selected_identity)
                self.assertEqual(selected_identity, identities[i])
                self.assertSequenceEqual(psk, psks[i])

        with open('ut_tls_13_server_parse_psk_extension_byte_outputs_temp', 'wb') as byte_output:
            with open('ut_tls_13_server_parse_psk_extension_int_outputs_temp.txt', 'w') as int_output:
                for psk, selected_identity in zip(psks_out, identities_out):
                    byte_output.write(psk)
                    int_output.write(f'\n{len(psk)} {selected_identity}\n')

    def test_tls_13_psk_key_schedule(self):
        key_sched_mult_out = []
        with open('ut_tls_13_psk_key_schedule_byte_inputs.txt', 'rb') as byte_input:
            with open('ut_tls_13_psk_key_schedule_int_inputs.txt', 'r') as int_input:
                input_bytes = byte_input.read()
                curr_pos = 0
                for _ in range(SAMPLES):
                    int_input.readline()
                    input_ints = int_input.readline().split()
                    csuite = int(input_ints[0])
                    psk_len = int(input_ints[1])
                    dhe_len = int(input_ints[2])
                    t_one_len = int(input_ints[3])
                    t_two_len = int(input_ints[4])
                    t_three_len = int(input_ints[5])
                    t_four_len = int(input_ints[6])
                    psk_secret = input_bytes[curr_pos:curr_pos + psk_len]
                    curr_pos += psk_len
                    dhe_secret = input_bytes[curr_pos:curr_pos + dhe_len]
                    curr_pos += dhe_len
                    t_one = input_bytes[curr_pos:curr_pos + t_one_len]
                    curr_pos += t_one_len
                    t_two = input_bytes[curr_pos:curr_pos + t_two_len]
                    curr_pos += t_two_len
                    t_three = input_bytes[curr_pos:curr_pos + t_three_len]
                    curr_pos += t_three_len
                    t_four = input_bytes[curr_pos:curr_pos + t_four_len]
                    curr_pos += t_four_len
                    PSK = PSKFunctions(None,None,None,None)
                    PSK.csuite = csuite
                    (secrets) = PSK.tls_13_psk_key_schedule(psk_secret, dhe_secret, t_one, t_two,t_three,t_four)
                    key_sched_mult_out.append(secrets)
        with open('ut_tls_13_psk_key_schedule_outputs_temp.txt', 'w') as filehandle:
            for (secrets) in key_sched_mult_out:
                key_sched_output = ""
                for i in range(len(secrets)):
                    key_sched_output = key_sched_output + secrets[i].hex()
                    filehandle.write('\n%s\n' % (key_sched_output))

        self.assertTrue(filecmp.cmp(
            'ut_tls_13_psk_key_schedule_outputs_temp.txt', 'ut_tls_13_psk_key_schedule_outputs.txt'))