#!/bin/python

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast

enc_data = bytes.fromhex("733358a68a8fe7d2f56c82fcb779c37801c6774637c47aedb0dd270a9b3eb3437cba53bb10a54fe1df3633085ebb652df866f0b0bdd99672f61953df31943a82c2c5f703766c98da4f90d3135072ab9658e313d2d4ecae07a0ea76a664038201ecbc28f331c59679a8ea4fcd51d9282bf8d9b41792401554d528c0c610ee71f7f9cd2b7f88f19c5b63f8a770c2c076693a64d8f4a7a4f650460b564d80941d2a96b0ad140c3adae3d15fc7451b7eb741cb05bcfcbc3da6247cf6f9a6cc27d25e93bbbe4015d5edae1cbc6de8e45c159589d48aeb871a575ac45ac38bd20eb425ed332ebbdec9a642dce71ba7a14caf05dd2744bf6be6a48e05a4ea7382208aaf")

if __name__ == "__main__":
    f = open("priv.pem")
    key = RSA.import_key(f.read())

    print(enc_data)

    dec_data = key.decrypt(enc_data)

    print(dec_data)
