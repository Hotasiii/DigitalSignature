# RSA Private and public key generator 
import random
import math
from sympy import *
import sympy.ntheory as nt
import hashlib

from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox

#Fungsi buat GUI
def start_menu(menu_awal):
    menu = Tk()
    menu_awal.destroy()
    window_setting(menu)

    # Label untuk input user manual
    label=Label(menu, text="Apa yang ingin dilakukan?", font=("Courier 22 bold"), wraplength=450)
    label.pack()

    #Setiap tombol mengarah ke menu masing-masing jenis cipher
    ttk.Button(menu, text= "Generate Public & Private Key",width= 40, command= lambda: generate_keypair()).pack(pady=20)
    ttk.Button(menu, text= "Digitally Sign a File",width= 40, command= lambda: open_file_sign(menu)).pack(pady=20)
    ttk.Button(menu, text= "Verify Digital Signature",width= 40, command= lambda: verify_menu(menu)).pack(pady=20)
# Fungsi untuk setting geometry window tk
def window_setting(menu):
    w = 700 # Lebar window menu
    h = 700 # Tinggu window menu

    # get screen width and height
    ws = menu.winfo_screenwidth() # lebar layar
    hs = menu.winfo_screenheight() # tinggi layar

    # Hitung koordinat x,y dari window menu
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)

    # Letak window menu di tengah layar
    menu.geometry('%dx%d+%d+%d' % (w, h, x, y))

def check_digital_signature(file_path, non_text_file, menu_verify):
    file = open(file_path, 'rt', encoding="latin-1")
    content = file.read()
    # Apabila pengguna sudah upload file non-teks, lalu mengupload file digital signature
    if (non_text_file != ''):
        signature_start_index = content.find('*** Begin of digital signature ***')
        signature_end_index = content.find('*** End of digital signature ***')
        print(signature_start_index, signature_end_index)
        # Apabila file tidak memiliki digital signature, maka akan dibalas dengan pesan error
        if ((signature_start_index == -1) or (signature_end_index == -1)):
            messagebox.showinfo(title="Error", message="File 'Digital_Signature.pri' kosong!")
            start_menu(menu_verify)
        else:
            # Mengembalikan message dan digital signature
            file = open(non_text_file, 'rt', encoding="latin-1")
            non_text_file_content = file.read()
            return(non_text_file_content, content[(signature_start_index+34):signature_end_index], menu_verify)
    # Apabila ini pertama kali pengguna upload file
    else:
        # Jika file yang diupload adalah file teks, dicari digital signature
        if (file_path[-3:] == 'txt'):
            signature_start_index = content.find('*** Begin of digital signature ***')
            signature_end_index = content.find('*** End of digital signature ***')
            # Apabila file tidak memiliki digital signature, maka akan dibalas dengan pesan error
            if ((signature_start_index == -1) or (signature_end_index == -1)):
                messagebox.showinfo(title="Error", message="File belum pernah ditandatangani sebelumnya!")
                start_menu(menu_verify)
            else:
                # Mengembalikan message dan digital signature
                # +34 di sini untuk melewati bagian "*** Begin of digital signature ***" dari teks agar indeks awal yang ingin diambil adalah dari signaturenya
                return(content[:signature_start_index], content[(signature_start_index+34):signature_end_index], menu_verify)
        # Jika file yang diupload adalah file non-teks
        else:
            label=Label(menu_verify, text="Upload file digital signature!", font=("Courier 15 bold"))
            label.pack()
            sign_path = filedialog.askopenfilename(title="Open a Text File", filetypes=(("all files","*.*"),("text files","*.txt")))
            return check_digital_signature(sign_path, file_path, menu_verify)

def verify_menu(menu):
    menu_verify = Tk()
    menu.destroy()
    window_setting(menu_verify)
    (message, sign, menu_verify_checked) = open_file_verify('', menu_verify)
    label=Label(menu_verify_checked, text="Upload Public Key!", font=("Courier 15 bold"))
    label.pack()
    (e, n, menu_verify_checked) = Key_Seperator(menu_verify_checked)
    print(e, n, message, sign)
    Verified = verify(message, sign, (int(e),int(n)))
    print(Verified)
    if (Verified == True):
        messagebox.showinfo(title="Information", message="Verifikasi berhasil!")
        start_menu(menu_verify_checked)
    else:
        messagebox.showinfo(title="Information", message="Verifikasi gagal!")
        start_menu(menu_verify_checked)

def open_file_verify(non_text_file, menu):
    menu_verify = Tk()
    menu.destroy()
    window_setting(menu_verify)
    #Non_text_file adalah variabel yang menunjukkan apakah pengguna sudah sebelumnya upload sebuah file non-teks
    label=Label(menu_verify, text="Upload File yang ingin diverifikasi!", font=("Courier 15 bold"))
    label.pack()
    file_path = filedialog.askopenfilename(title="Open a Text File", filetypes=(("all files","*.*"),("text files","*.txt") ))
    (message, sign, menu_verify_checked) = check_digital_signature(file_path, non_text_file, menu_verify)
    return (message, sign, menu_verify_checked)

def open_file_sign(menu):
    menu_sign = Tk()
    menu.destroy()
    window_setting(menu_sign)

    label=Label(menu_sign, text="Upload File yang ingin ditandatangani!", font=("Courier 15 bold"))
    label.pack()

    file_path = filedialog.askopenfilename(title="Open a Text File", filetypes=(("all files","*.*"),("text files","*.txt")))
    file = open(file_path, 'rt', encoding="latin-1")
    content = file.read()
    file.close()
    #Mengecek apakah file sudah ditanda tangan atau belum.
    signature_start_index = content.find('*** Begin of digital signature ***')
    signature_end_index = content.find('*** End of digital signature ***')
    # Apabila file memiliki digital signature, maka akan dikembalikan error
    if ((signature_start_index != -1) or (signature_end_index != -1)):
        messagebox.showinfo(title="Error", message="File sudah ditandatangani sebelumnya!")
        start_menu(menu_sign)
    else:
        label=Label(menu_sign, text="Upload Private Key!", font=("Courier 15 bold"))
        label.pack()
        (d, n, menu_signed) = Key_Seperator(menu_sign)
        digital_signature = sign(content, (d,n))
        #Jika file yang ditanda tangan adalah teks, maka signature ditambahkan di akhir teks
        if (file_path[-3:] == 'txt'):
            file = open(file_path, 'a')
            file.write("*** Begin of digital signature ***" + digital_signature + "*** End of digital signature ***")
            file.close()
            messagebox.showinfo(title="Success", message="File telah ditandatangani!")
            start_menu(menu_signed)
        #Jika file yang ditanda tangan bukan teks. maka signature disimpan dalam file teks eksternal
        else:
            file = open('key/Digital_Signature.pri', 'a') # Cipta file jika belum ada
            file = open('key/Digital_Signature.pri', 'r')
            content = file.read()
            print(content)
            if (content == ''):
                file = open('key/Digital_Signature.pri', 'a')
                file.write("*** Begin of digital signature ***" + digital_signature + "*** End of digital signature ***")
                file.close()
                messagebox.showinfo(title="Success", message="File telah ditandatangani! Digital Signature dapat ditemukan pada file 'Digital_Signature.pri'.")
                start_menu(menu_signed)
            else:
                messagebox.showinfo(title="Error", message="File sudah ditandatangani sebelumnya!")
                start_menu(menu_signed)

def Key_Seperator(menu):
    file_path = filedialog.askopenfilename(title="Open a Text File", filetypes=(("all files","*.*"),("text files","*.txt")))
    file = open(file_path, 'rt', encoding="latin-1")
    content = file.read()
    i = 0
    key = ''
    n = ''
    while (i < len(content)):
        if (content[i] != ' '):
            key += content[i]
            i += 1
        else:
            n = content[i+1:len(content)]
            i = len(content)
    print(key, n)
    return (int(key), int(n), menu)

    


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
    p = primegenerator()
    q = primegenerator()

    # Apabila p dan q sama, maka perlu dirandom ulang
    while (p == q):
        p = primegenerator()
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
    privateFile = open("key/key_rsa_private.pri", "w")
    publicFile = open("key/key_rsa_public.pri", "w")

    # isi file dengan key
    
    privateFile.write(str(d) + " " + str(n))
    publicFile.write(str(e) + " " + str(n))

    privateFile.close()
    publicFile.close()    

    # public key, private key
    messagebox.showinfo(title="Saved", message="Public dan Private Key disimpan dalam folder 'key'")
    return ((e, n), (d, n))

# Algoritma RSA
def RSAEncrypt(plaintext, privateKey):
    d, n = privateKey
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
    e, n = publicKey
    blocksize = (n.bit_length() + 7) // 8

    cipherBlocks, padding = ciphertext[:-4], int.from_bytes(ciphertext[-4:], byteorder='big', signed=False)
    cipherBlocks = [int.from_bytes(cipherBlocks[i:i+blocksize], byteorder='big', signed=False) for i in range(0, len(cipherBlocks), blocksize)]
    print(cipherBlocks)

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

menu = Tk()
start_menu(menu)
menu.mainloop()