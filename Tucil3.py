# RSA Private and public key generator 
import random
import math
from sympy import *
import sympy.ntheory as nt
import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a  

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)
    
def primegenerator():
    while True:
        result = random.randint(0, 100000000)
        if nt.isprime(result):
            return result
    
def generate_keypair():
    p  = primegenerator()
    q = primegenerator()

    n = p * q 
    phi = (p-1) * (q-1)
    e = random.randrange(1, phi)

    g = gcd(e, phi)
    
    # e relatif prima dengan phi 
    while (g != 1):
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # kunci dekripsi, invers modulo
    d = extended_gcd(e, phi)[1]

        # open file private and public
    privateFile = open("key/id_rsa.pri", "w")
    publicFile = open("key/id_rsa.pub", "w")

    # replace key
    privateFile.write(str(d) + " " + str(n))
    publicFile.write(str(e) + " " + str(n))

    privateFile.close()
    publicFile.close()    

    # Public key, private key
    return ((e, n), (d, n))

# Algoritma RSA
def rsa_encrypt(plaintext, privateKey):
    d, n = privateKey
    blocksize = math.ceil(math.log2(n) / 8)

    bytesPlaintext = bytes.fromhex(plaintext)
    plainBlocks = [bytesPlaintext[i:i+blocksize-1] for i in range(0, len(bytesPlaintext), blocksize-1)]
    
    for i in range(len(plainBlocks)):
        pad_length = blocksize - len(plainBlocks[i])
        if pad_length:
            plainBlocks[i] = b'\x00' * pad_length + plainBlocks[i]
        plainBlocks[i] = int.from_bytes(plainBlocks[i], byteorder='big', signed=False)

    cipherBlocks = [pow(plain_block, d, n) for plain_block in plainBlocks]

    bytesCiphertext = b''.join([cipher_block.to_bytes(length=blocksize, byteorder='big', signed=False) for cipher_block in cipherBlocks])
    pad_length_bytes = (blocksize - len(bytesPlaintext) % blocksize).to_bytes(length=4, byteorder='big', signed=False)
    bytesCiphertext += pad_length_bytes

    return bytesCiphertext.hex()

def rsa_decrypt(ciphertext, publicKey):
    e, n = publicKey
    blocksize = math.ceil(math.log2(n) / 8)

    bytesCiphertext = bytes.fromhex(ciphertext)
    cipherBlocks = [int.from_bytes(bytesCiphertext[i:i+blocksize], byteorder='big', signed=False) for i in range(0, len(bytesCiphertext)-4, blocksize)]
    pad_length = int.from_bytes(bytesCiphertext[-4:], byteorder='big', signed=False)

    plainBlocks = [pow(cipher_block, e, n) for cipher_block in cipherBlocks]
    bytesPlaintext = b''.join([plain_block.to_bytes(length=blocksize, byteorder='big', signed=False) for plain_block in plainBlocks])

    if pad_length > 0:
        bytesPlaintext = bytesPlaintext[:-pad_length]

    return bytesPlaintext.hex()

# Algoritma Hash SHA-3 
def sha3(message):
    hashed = hashlib.sha3_256(message.encode("latin-1")).hexdigest()
    return hashed

# Menu verifikasi tanda tangan digital (verifying)
def verify(message, sign, publicKey):
    sign = bytes.fromhex(sign)
    print(sha3(message))
    print(rsa_decrypt(sign, publicKey))

    return sha3(message) == rsa_decrypt(sign, publicKey)

# Pembangkitan tanda tangan digital (signing)
def sign(message, privateKey):
    msg_digest = sha3(message)
    msg_digest = bytes.fromhex(msg_digest)
    signed = rsa_encrypt(msg_digest, privateKey)

    return signed 


######################################################## 
# RSA Algorithm other ver.  

# def rsa_encrypt(plaintext, privateKey):
#     d, n = privateKey, privateKey
#     blocksize = math.ceil(math.log2(n)/8)

#     plain_blocks = [b'\x00' + plaintext[i:i+blocksize-1]]
#     for i in range(0, len(plaintext), blocksize-1):
#         pad_length = blocksize-len(plain_blocks[-1])
#         if pad_length:
#             plain_blocks[-1] = b'\x00' * pad_length + plain_blocks[-1]
        
#         plain_blocks = [int.from_bytes(byte, byteorder='big', signed=False) for byte in plain_blocks]

#         cipher_blocks = []
#         for i in range(len(plain_blocks)):
#             cipher_blocks.append(pow(plain_blocks[i], d, n))

#         cipher_blocks = [block.to_bytes(length=blocksize, byteorder='big', signed=False) for block in cipher_blocks]

#         ciphertext = b''
#         for block in cipher_blocks:
#             ciphertext += block
#         ciphertext += pad_length.to_bytes(length=4, byteorder='big', signed=False)

#         ciphertext_str = ciphertext.hex()

#         return (ciphertext_str)
    

# def rsa_decrypt(ciphertext, publicKey):

#     e, n = publicKey
#     blocksize = math.ceil(math.log2(n)/8)

#     cipher_blocks, padding = ciphertext[:-4], int.from_bytes(ciphertext[-4:], byteorder='big', signed=False)

#     cipher_blocks = [cipher_blocks[i:i+blocksize] for i in range(0, len(cipher_blocks), blocksize)]

#     cipher_blocks = [int.from_bytes(byte, byteorder='big', signed=False) for byte in cipher_blocks]

#     plain_blocks = []
#     for i in range(len(cipher_blocks)):
#         plain_blocks.append(pow(cipher_blocks[i], e, n))

#     plain_blocks = [block.to_bytes(length=blocksize, byteorder='big', signed=False) for block in plain_blocks]

#     plain_blocks[-1] = plain_blocks[-1][padding:]

#     plain_blocks = [block[1:] for block in plain_blocks]

#     plaintext = b''
#     for block in plain_blocks:
#         plaintext += block

#     plaintext_str = plaintext.hex()

#     return(plaintext_str)