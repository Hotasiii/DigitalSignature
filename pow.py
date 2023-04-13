n = 419165334221155
blocksize = (n.bit_length() + 7) // 8
print(pow(1849994800534425, -1818800048789069, n).to_bytes(length=blocksize, byteorder='big', signed=False))