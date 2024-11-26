#!/bin/python3

import sys
import struct
import pathlib
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def decrypt_sealed_sender_message(data, key):
    # decrypt data via AES 256 in CTR Mode
    cipher = AES.new(key, AES.MODE_CTR, initial_value=bytearray(8), nonce=bytearray(8))
        
    return cipher.decrypt(data)

def decrypt_message(data, key, iv):
    # decrypt data via AES 256 in CBC Mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return cipher.decrypt(pad(data, AES.block_size))

def parse_keyfile(path):
    # open and parse keyfile
    list = {}
    with open(path, 'r') as file:
        for line in file:
            tokens = line.replace('\n', '').replace('\r', '').split(' ')
            list[bytes.fromhex(tokens[0])] = tokens[1:]
    return list

def main():
    # setup argparse and parse command line arguments
    parser = argparse.ArgumentParser(
                prog='sigpkgdecrypt',
                description='Decrypt raw data of the message[].content field in Signals PUT message websocket request')
    parser.add_argument('encrypted_file_path', nargs='+', metavar='file', type=str,
                help='File containing the raw binary data of the message contennt field')
    parser.add_argument('-sk', '--sealed-sender-key', nargs=1, metavar='SKEY', type=str,
                help='Key used to encrypt the message in sealed_sender_encrypt_from_usmc (hex string)',
                required=False)
    parser.add_argument('-k', '--key', nargs=1, metavar='KEY', type=str,
                help='Key used to encrypt the message in message_encrypt (hex string)',
                required=False)
    parser.add_argument('-iv', '--initialization-vector', nargs=1, metavar='IV', type=str,
                help='IV used to encrypt the message in message_encrypt (hex string)',
                required=False)
    parser.add_argument('-ds', '--dump-unsealed-message', action='store_true',
                help='Dump the unsealed sender message',
                required=False)
    parser.add_argument('-de', '--dump-encrypted-message', action='store_true',
                help='Dump the encrypted message',
                required=False)
    parser.add_argument('-kf', '--key-file', nargs=1, type=str,
                help='File containing all the ciphertext-ids, keys and ivs of the packages (required if count of files is greater than 1)',
                required=False)

    args = parser.parse_args()

    #print(args)

    encrypted_filepath_list = args.encrypted_file_path

    # check if all necessary arguments were specified
    key_list = None
    if len(encrypted_filepath_list) > 1 and args.key_file == None:
        print("Multiple files to decrypt. Option -kf missing.")
        sys.exit(1)
    elif len(encrypted_filepath_list) > 1:
        key_list = parse_keyfile(args.key_file[0])

    message_key = None
    message_iv  = None
    sealed_sender_key = None
    if len(encrypted_filepath_list) == 1 and (args.key == None or args.initialization_vector == None or args.sealed_sender_key == None):
        print("Single file to decrypt. Options -iv, -k, -sk required.")
        sys.exit(1)
    elif len(encrypted_filepath_list) == 1:
        # get keys and iv
        message_key = bytes.fromhex(args.key[0])
        message_iv  = bytes.fromhex(args.initialization_vector[0])
        sealed_sender_key = bytes.fromhex(args.sealed_sender_key[0])
    
    # open binary message content file and decrypt contents
    for encrypted_filepath in encrypted_filepath_list:
        with open(encrypted_filepath, 'rb') as file:
            raw_ciphertext = file.read()

            if len(encrypted_filepath_list) > 1:
                sealed_sender_key = bytes.fromhex(key_list[raw_ciphertext[:8]][0])

            unsealed_sender_ciphertext = decrypt_sealed_sender_message(raw_ciphertext, sealed_sender_key)

            if args.dump_unsealed_message:
                with open(encrypted_filepath + '.unsealed.dat', 'wb') as outfile:
                    outfile.write(unsealed_sender_ciphertext)

            # remove meta data
            encrypted_message = unsealed_sender_ciphertext[325:]
            # remove hmac
            encrypted_message = encrypted_message[:-32]

            if args.dump_encrypted_message:
                with open(encrypted_filepath + '.encrypted.dat', 'wb') as outfile:
                    outfile.write(encrypted_message)

            if len(encrypted_filepath_list) > 1:
                message_key = bytes.fromhex(key_list[encrypted_message[:8]][0])
                message_iv  = bytes.fromhex(key_list[encrypted_message[:8]][1])

            uncrypted_message = decrypt_message(encrypted_message, message_key, message_iv)

            with open(encrypted_filepath + '.decrypted.dat', 'wb') as outfile:
                outfile.write(uncrypted_message)

    sys.exit(0)

if __name__ == "__main__":
    main()
