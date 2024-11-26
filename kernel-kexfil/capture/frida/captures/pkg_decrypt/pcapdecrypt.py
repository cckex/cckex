#!/bin/python3

import re
import sys
import json
import base64
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

def getWebsocketBinaryData(jsonData):
    try:
        return bytes.fromhex(jsonData['_source']['layers']['data']['data.data'].replace(':',''))
    except:
        return None

def getEncryptedSealedSenderData(binData):

    tokens = re.findall('"messages":\[\{"content":.*=","', str(binData))

    if(len(tokens) == 0):
        print('[error] getEncryptedSealedSenderData: len(tokens) == 0')
        return None
    elif(len(tokens) > 1):
        print('[warn] len(tokens) > 1')
  
    print(tokens[0][24:-3])

    return base64.b64decode(tokens[0][24:-3])[84:]

def main():
    # setup argparse and parse command line arguments
    parser = argparse.ArgumentParser(
                prog='sigpkgdecrypt',
                description='Decrypt raw data of the message[].content field in Signals PUT message websocket request')
    parser.add_argument('json_file_path', nargs=1, metavar='file', type=str,
                help='JSON File containing the dissected tls traffic.')
    parser.add_argument('-ds', '--dump-sealed-message', action='store_true',
                help='Dump the sealed sender message.',
                required=False)
    parser.add_argument('-du', '--dump-unsealed-message', action='store_true',
                help='Dump the unsealed sender message.',
                required=False)
    parser.add_argument('-de', '--dump-encrypted-message', action='store_true',
                help='Dump the encrypted message (inner message in the sealed sender)',
                required=False)
    parser.add_argument('-dd', '--dump-decrypted-message', action='store_true',
                help='Dump the decrypted message (inner message in the sealed sender)',
                required=False)
    parser.add_argument('-kf', '--key-file', nargs=1, type=str,
                help='File containing all the ciphertext-ids, keys and ivs of the packages',
                required=True)

    # parse and extract arguments
    args = parser.parse_args()

    #print(args)

    json_filepath = args.json_file_path[0]
    key_list = parse_keyfile(args.key_file[0])

    putMessageIdentifier = b'\x50\x55\x54\x12\x3d\x2f\x76\x31\x2f\x6d\x65\x73\x73\x61\x67\x65\x73\x2f'

    # open and parse json file
    counter = 0
    with open(json_filepath) as jsonFile:
        jsonDataList = json.load(jsonFile)
        for jsonData in jsonDataList:
            print("\r[info] Checking Package " + str(counter) + "..", end="")
            counter += 1
            
            binaryPkgData = getWebsocketBinaryData(jsonData)

            if(binaryPkgData == None): continue

            # identify Put-Message messages
            if(binaryPkgData[7:25] != putMessageIdentifier):
               continue

            print("\n[info] Found Package with '" + str(putMessageIdentifier) + "'")

            # extract and decrypt sealed sender binary data
            raw_ciphertext = getEncryptedSealedSenderData(binaryPkgData)

            if args.dump_sealed_message:
                with open('message' + str(counter) + '.sealed_sender.raw', 'wb') as outfile: outfile.write(raw_ciphertext)

            sealed_sender_key = None
            try:
                sealed_sender_key = bytes.fromhex(key_list[raw_ciphertext[:8]][0])
            except:
                print('[error] unable to find corresponding sealed session key with id = ' + raw_ciphertext[:8].hex())
                continue
            unsealed_sender_ciphertext = decrypt_sealed_sender_message(raw_ciphertext, sealed_sender_key)

            if args.dump_unsealed_message:
                with open('message' + str(counter) + '.unsealed_sender.raw', 'wb') as outfile: outfile.write(unsealed_sender_ciphertext)

            # remove meta data
            encrypted_message = unsealed_sender_ciphertext[325:]
            # remove hmac
            encrypted_message = encrypted_message[:-32]

            if args.dump_encrypted_message:
                with open('message' + str(counter) + '.encrypted.raw', 'wb') as outfile: outfile.write(encrypted_message)

            try:
                message_key = bytes.fromhex(key_list[encrypted_message[:8]][0])
                message_iv  = bytes.fromhex(key_list[encrypted_message[:8]][1])
            except:
                print('[error] unable to find corresponding message key / iv with id = ' + encrypted_message[:8].hex())
                continue

            uncrypted_message = decrypt_message(encrypted_message, message_key, message_iv)

            with open('message' + str(counter) + '.decrypted.raw', 'wb') as outfile: outfile.write(uncrypted_message)
        
    sys.exit(0)

if __name__ == "__main__":
    main()
