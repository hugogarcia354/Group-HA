
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization,hashes 
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.asymmetric as asymm
from pathlib import Path

def keys():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )

    f = open('private_key.pem','wb')
    f.write(private_key)
    f.close()

    public = key.public_key()
    public_key = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    f = open('public_key.pem','wb')
    f.write(public_key)
    f.close()

def MyEncrypt(message,key):
    if(len(key)< 32):
        return "Error: Short Key"
    IV = os.urandom(16)
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    messagePadded = padder.update(message)
    messagePadded += padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(messagePadded) + encryptor.finalize()
    return ct,IV
    
def MyDecrypt(ct,IV,key):
    unpadder = padding.PKCS7(128).unpadder()
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    message = unpadder.update(message)
    message += unpadder.finalize()
    return message

def MyfileEncrypt(filepath):
   
    ext = Path(filepath).suffix
    if(ext =='.txt'):
        f = open(filepath,'r')
        content = f.read()
        content=content.encode()
        filepath = 'fooE.txt'
    elif(ext == '.jpg'):
        f = open(filepath,'rb')
        content = f.read()
        filepath = 'fooE.jpg'
    else:
        print("Cannot encrypt filetype.")
    f.close()
    key = os.urandom(32)
    ct,IV = MyEncrypt(content,key)
    f = open(filepath,'wb')
    f.write(ct)
    f.close()
    return ct,IV,key,ext,filepath
    
def MyfileDecrypt(filepath,ct,IV,key,ext):
    f = open(filepath,'rb')
    content = f.read()
    f.close()
    message = MyDecrypt(content,IV,key)
    if(ext == '.txt'):
        message = message.decode()
        f = open('fooD.txt','w')
        f.write(message)
        f.close()
    elif(ext =='.jpg'):
        f = open('fooD.jpg','wb')
        f.write(message)
        f.close()
    else:
        print("Cannot decrypt filetype.")
    return message

def MyRSAEncrypt(filepath,RSA_Publickey_filepath):
    ct,IV,key,ext = MyfileEncrypt(filepath)

    key_file = open(RSA_Publickey_filepath,'rb')
    
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
        )
    key_file.close()
    RSAc = public_key.encrypt(
        key,
        asymm.padding.OAEP(
            mgf = asymm.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return RSAc,ct,IV,ext

def MyRSADecrypt(RSAc,ct,IV,filename,ext,RSA_Privatekey_filepath):
    key_file = open(RSA_Privatekey_filepath,'rb')
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
        )
    key_file.close()
    key = private_key.decrypt(
        RSAc,
        asymm.padding.OAEP(
                mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
        )
    MyfileDecrypt(filename,ct,IV,key,ext)
#filename = 'Picture.jpg'
cipher,IV, key, ext, filename = MyfileEncrypt('Picture.jpg')
MyfileDecrypt(filename, cipher, IV,key, ext)

#keys()

#RSAcipher,ct,IV,ext = MyRSAEncrypt(filename,'public_key.pem')
#MyRSADecrypt(RSAcipher,ct,IV,filename,ext,'private_key.pem')
    

