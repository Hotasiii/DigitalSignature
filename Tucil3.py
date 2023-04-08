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
    
    # Kondisi: e relatif prima dengan phi 
    while (g != 1):
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # kunci dekripsi, invers modulo
    d = extended_gcd(e, phi)[1]

    # open dan write file private and public dengan e, d, dan n
    privateFile = open("key/id_rsa.pri", "w")
    publicFile = open("key/id_rsa.pub", "w")

    # isi file dengan key
    privateFile.write(str(d) + " " + str(n))
    publicFile.write(str(e) + " " + str(n))

    privateFile.close()
    publicFile.close()    

    # public key, private key
    return ((e, n), (d, n))

# Algoritma RSA
def RSAEncrypt(plaintext, privateKey):
    d, n = privateKey, privateKey
    blocksize = math.ceil(n.bit_length() / 8)

    plainBlocks = [bytes.fromhex('00') + plaintext[i:i+blocksize-1] for i in range(0, len(plaintext), blocksize-1)]

    pad_length = blocksize - len(plainBlocks[-1])
    if pad_length:
        plainBlocks[-1] = bytes.fromhex('00') * pad_length + plainBlocks[-1]

    plainBlocks = [int.from_bytes(byte, byteorder='big', signed=False) for byte in plainBlocks]

    cipherBlocks = [pow(block, d, n) for block in plainBlocks]

    cipherBlocks = [block.to_bytes(length=blocksize, byteorder='big', signed=False) for block in cipherBlocks]

    ciphertext = b''.join(cipherBlocks)
    ciphertext += pad_length.to_bytes(length=4, byteorder='big', signed=False)

    return ciphertext.hex()

def RSADecrypt(ciphertext, publicKey):
    e, n = publicKey, publicKey
    blocksize = (n.bit_length() + 7) // 8

    cipherBlocks, padding = ciphertext[:-4], int.from_bytes(ciphertext[-4:], byteorder='big', signed=False)
    cipherBlocks = [int.from_bytes(cipherBlocks[i:i+blocksize], byteorder='big', signed=False) for i in range(0, len(cipherBlocks), blocksize)]

    plainBlocks = [pow(c, e, n).to_bytes(length=blocksize, byteorder='big', signed=False) for c in cipherBlocks]
    plainBlocks[-1] = plainBlocks[-1][padding:]

    plaintext = b''.join(block[1:] for block in plainBlocks)

    return plaintext.hex()

# Algoritma Hash SHA-3 
def sha3(message):
    hashedMessage = hashlib.sha3_256(message.encode("latin-1")).hexdigest()
    return hashedMessage

# Menu verifikasi tanda tangan digital (verifying)
def verify(message, sign, publicKey):
    sign = bytes.fromhex(sign)
    print(sha3(message))
    print(RSADecrypt(sign, publicKey))

    return sha3(message) == RSADecrypt(sign, publicKey)

# Pembangkitan tanda tangan digital (signing)
def sign(message, privateKey):
    message_digest = sha3(message)
    message_digest = bytes.fromhex(message_digest)
    sign = RSAEncrypt(message_digest, privateKey)

    return sign 
    

#### Test
# print(sha3('halo'))
# print(generate_keypair())
# print(sign('./test.txt', 605087519906351))
# print(verify('./test.txt', "00e84ddc7f54100115d7996f8b1500a2ec93e3c793011201c42977ca020c5efed419b900785fa5ec90cb00000004", 1371845172700751))
