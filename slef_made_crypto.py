"""
crypto for python
"""

import base64
import os
import array
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import random
import binascii
import base64


class CRYPTO:
    def __init__(self):
        print('crypto start')

    def r(self):

        # key = array.array('B', random.sample(range(256), 16))
        r = [0X57,0X83,0XD5,0X21,0X56,0XAD,0X6F,0X0E,0X63,0X88,0X27,0X4E,0XC6,0X70,0X2E, 0XE0]
        # print('r in crypto', r)
        # print(type(key))
        r_list = []
        for i in r:
            r_list.extend([i])
        r = array.array('B', r_list)
        return r

    def c1(self, k, r, pres, preq, iat, ia, rat, ra):
        #k TK
        #r random request
        #pres response data
        #preq  request datat
        #iat initiator type
        #ia initiator address
        #rat responsor type
        #ra responsor address
        # ia = array.array('B', [0XA1, 0XA2, 0XA3, 0XA4, 0XA5, 0XA6])
        # ra = array.array('B', [0XB1, 0XB2, 0XB3, 0XB4, 0XB5, 0XB6])
        # iat =  array.array('B', [0x01])
        # rat =  array.array('B', [0x00])
        # preq_list =  array.array('B', [0x07, 0x07, 0x10, 0x00, 0x00, 0x01, 0x01])
        # pres =  array.array('B', [0x05, 0x00, 0x08, 0x00, 0x00, 0x03, 0x02])
        print('ia: ', ia)
        print('ra: ', ra)
        print('iat: ', iat)
        print('rat: ', rat)
        print('preq: ', preq)
        print('pres: ', pres)
        preq_list = []
        preq = [bytes([c]) for c in preq]
        for i in preq:
            preq_list.extend([int.from_bytes(i, byteorder='little')])

        preq_list = array.array('B', preq_list)
        # preq_list[3] = 0x01
        print('preq_list: ', preq_list)
        p1 = pres + preq_list + rat + iat
        p1 = bytearray(p1)
        # print('p1: ', p1)

        p2 =  array.array('B', [0] * 4) + ia + ra
        #r is key
        # print('p2: ', p2)
        res = self.xor(r, p1)
        res = self.e(k, res)
        res = self.xor(res, p2)
        res = bytearray(self.e(k, res))
        print('res: ', res)
        res_list =[]
        for i in res:
            res_list.extend([i])
        res = array.array('B', res_list)
        print('res_list: ', res)
        return res

    def s1(self, k, r1, r2):
        print('r1', r1)
        print('r2', r2)
        return self.e(k, r2[0:8] +
                      r1[0:8]
                     )

    # def e(self, key, data):
    #     data = bytes(data)
    #     print('data from encrypt_token: ', data)
    #     key = bytes(key)
    #     print('key from encrypt_token: ', key)
    #     print('block size: ', AES.block_size)
    #     IV = Random.new().read(AES.block_size)
    #     # binascii.hexlify(IV)
    #     aes = AES.new(key, AES.MODE_ECB, IV)
    #     # aes = AES.new(key, AES.MODE_ECB)
    #     return aes.encrypt(data)

    def e(self, key, data):
        data = bytes(data)
        # print('data from encrypt_token: ', data)
        key = bytes(key)
        # print('key from encrypt_token: ', key)
        aes = AES.new(key)
        result = aes.encrypt(data)
        return result

    def _pad(self, s):
        # print(s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size))
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode('utf-8')


    def xor(self, b1, b2):
        # print('b1: ', b1)
        # print('b2: ', b2)
        # result = list(range(len(b1))
        # result = array.array('B', [0]*len(b1))
        result = list(range(len(b1)))
        i = 0
        for i in range(0, len(b1)):
            result[i] = b1[i] ^ b2[i]
        # print('result: ', result)
        return result

    def bytes_to_int(self, bytes):
        result = 0

        for b in bytes:
            result = result * 256 + int(b)

        return result

    def swap(self, INPUT):
        # output = list(range(len(INPUT)))
        output = array.array('B', [0] * len(INPUT))
        i = 0
        for i in range(0, len(output)):
            output[i] = INPUT[len(INPUT)-i-1]

        return output

crypto = CRYPTO()
