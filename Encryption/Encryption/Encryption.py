
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization,hashes, hmac 
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.asymmetric as asymm
from pathlib import Path


#generate public and private keys
def keys():

    #generate RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    #create a private key from the RSA key
    private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )

    #save the private key as a .pem file
    f = open('private_key.pem','wb')
    f.write(private_key)
    f.close()

    #create a public key from the RSA key
    public = key.public_key()
    public_key = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #save the public key as a .pem file
    f = open('public_key.pem','wb')
    f.write(public_key)
    f.close()

    #encrypt message
def MyEncrypt(message,key):
    #verify that the key is at least 32 bytes
    if(len(key)< 32):
        return "Error: Short Key"
    #create 16 byte random IV.
    IV = os.urandom(16)
    backend = default_backend()
    #pad message to 128 bits
    padder = padding.PKCS7(128).padder()
    messagePadded = padder.update(message)
    messagePadded += padder.finalize()
    #initiate cipher with key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    #encrypt message
    ct = encryptor.update(messagePadded) + encryptor.finalize()
    return ct,IV
    
#decrypt message
def MyDecrypt(ct,IV,key):
    unpadder = padding.PKCS7(128).unpadder()
    backend = default_backend()
    #initiate cipher with key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    #decrypt message
    decryptor = cipher.decryptor()
    message = decryptor.update(ct) + decryptor.finalize()
    #unpad message
    message = unpadder.update(message)
    message += unpadder.finalize()
    return message

#encrypt a file
def MyfileEncrypt(filepath):
   #get type of file
    ext = Path(filepath).suffix
    #get file name
    filename = Path(filepath).stem
    #check if text file, if so then encode to byte
    if(ext =='.txt'):
        f = open(filepath,'r')
        content = f.read()
        content=content.encode()
        #attach encr to name
        filename=filename+'_Encr'+ext
        filepath = filename
    #else it assumes its a byte file
    else:
        f = open(filepath,'rb')
        content = f.read()
        #attach encr to name
        filename=filename+'_Encr'+ext
        filepath = filename
    f.close()
    #generate key
    key = os.urandom(32)
    #encrypt
    ct,IV = MyEncrypt(content,key)
    #write encrypted file
    f = open(filepath,'wb')
    f.write(ct)
    f.close()
    return ct,IV,key,ext
    
#decrypt a file
def MyfileDecrypt(filepath,ct,IV,key,ext):
    #open file and read
    f = open(filepath,'rb')
    content = f.read()
    f.close()
    #decrypt message
    message = MyDecrypt(content,IV,key)
    #add decr to name
    filename = Path(filepath).stem
    filename= filename +'_Decr'+ext
    #check if file type is text, is so, decode then write
    if(ext == '.txt'):
        message = message.decode()
        f = open(filename,'w')
        f.write(message)
        f.close()
    #else just write
    else:
        f = open(filename,'wb')
        f.write(message)
        f.close()
    return message

#encrypt using RSA
def MyRSAEncrypt(filepath,RSA_Publickey_filepath):
    #encrypt file
    ct,IV,key,ext = MyfileEncrypt(filepath)
    #load public key file
    key_file = open(RSA_Publickey_filepath,'rb')
    
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
        )
    key_file.close()
    #encrypt using OAEP
    RSAc = public_key.encrypt(
        key,
        asymm.padding.OAEP(
            mgf = asymm.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return RSAc,ct,IV,ext

#decrypt RSA encryption 
def MyRSADecrypt(RSAc,ct,IV,filename,ext,RSA_Privatekey_filepath):
    #load private key
    key_file = open(RSA_Privatekey_filepath,'rb')
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
        )
    key_file.close()
    #decrypt using private key
    key = private_key.decrypt(
        RSAc,
        asymm.padding.OAEP(
                mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
        )
    #decrypt file
    MyfileDecrypt(filename,ct,IV,key,ext)

  #encrypt-then-MAC message
def MyEncryptMAC(message,EncKey,HMACKey):
    #verify that the key is at least 32 bytes
    if(len(EncKey)< 32):
        return "Error: Short Key"
    #create 16 byte random IV.
    IV = os.urandom(16)
    backend = default_backend()
    #pad message to 128 bits
    padder = padding.PKCS7(128).padder()
    messagePadded = padder.update(message)
    messagePadded += padder.finalize()
    #initiate cipher with key and IV
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    #encrypt message
    ct = encryptor.update(messagePadded) + encryptor.finalize()
    #MAC message
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=backend)
    h.update(ct)
    tag = h.finalize()
    return ct,IV,tag

#MAC Verify then decrypt message
def MyDecryptMAC(ct,IV,key,tag,HMACKey):
    backend = default_backend()
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=backend)
    h.update(ct)
    h = h.finalize()
    if(tag==h):
        unpadder = padding.PKCS7(128).unpadder()
        backend = default_backend()
        #initiate cipher with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
        #decrypt message
        decryptor = cipher.decryptor()
        message = decryptor.update(ct) + decryptor.finalize()
        #unpad message
        message = unpadder.update(message)
        message += unpadder.finalize()
        return message
    else:
        return "Invalid"

#encrypt-then-MAC file
def MyfileEncryptMAC(filepath):
    #get type of file
    ext = Path(filepath).suffix
    #get file name
    filename = Path(filepath).stem
    #check if text file, if so then encode to byte
    if(ext =='.txt'):
        f = open(filepath,'r')
        content = f.read()
        content=content.encode()
        #attach encr to name
        filename=filename+'_Encr'+ext
        filepath = filename
    #else it assumes its a byte file
    else:
        f = open(filepath,'rb')
        content = f.read()
        #attach encr to name
        filename=filename+'_Encr'+ext
        filepath = filename
    f.close()
    #generate keys
    EncKey = os.urandom(32)
    HMACKey = os.urandom(32)
    #encrypt
    ct,IV,tag = MyEncryptMAC(content,EncKey,HMACKey)
    #write encrypted file
    f = open(filepath,'wb')
    f.write(ct)
    f.close()
    return ct,IV,tag,EncKey,HMACKey,ext

#MAC Verify then decrypt file
def MyfileDecryptMAC(filepath,ct,IV,tag,EncKey,HMACKey,ext):
    #open file and read
    f = open(filepath,'rb')
    content = f.read()
    f.close()
    #decrypt message
    message = MyDecryptMAC(content,IV,EncKey,tag,HMACKey)
    if(message == "Invalid"):
        return "Invalid"
    else:
        #add decr to name
        filename = Path(filepath).stem
        filename= filename +'_Decr'+ext
        #check if file type is text, is so, decode then write
        if(ext == '.txt'):
            message = message.decode()
            f = open(filename,'w')
            f.write(message)
            f.close()
        #else just write
        else:
            f = open(filename,'wb')
            f.write(message)
            f.close()
        return message

#encrypt-then-mac using RSA
def MyRSAEncryptMAC(filepath,RSA_Publickey_filepath):
    #encrypt file
    ct,IV,tag,key,hkey,ext = MyfileEncryptMAC(filepath)
    #load public key file
    key_file = open(RSA_Publickey_filepath,'rb')
    
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
        )
    key_file.close()
    #encrypt using OAEP
    m = key+hkey
    RSAc = public_key.encrypt(
        m,
        asymm.padding.OAEP(
            mgf = asymm.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return RSAc,ct,IV,tag,ext

#MAC Verify then decrypt RSA encryption 
def MyRSADecryptMAC(RSAc,ct,IV,tag,filename,ext,RSA_Privatekey_filepath):
    #load private key
    key_file = open(RSA_Privatekey_filepath,'rb')
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
        )
    key_file.close()
    #decrypt using private key
    key = private_key.decrypt(
        RSAc,
        asymm.padding.OAEP(
                mgf=asymm.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
        )
    a = key
    EncKey = a[0:32]
    HMACKey = a[32:64]
    #decrypt file
    MyfileDecryptMAC(filename,ct,IV,tag,EncKey,HMACKey,ext)

#generate keys
#keys()

filename = 'Picture.jpg'
RSAcipher,ct,IV,tag,ext = MyRSAEncryptMAC(filename,'public_key.pem')
filename=Path(filename).stem +"_Encr"+ ext
MyRSADecryptMAC(RSAcipher,ct,IV,tag,filename,ext,'private_key.pem')


#test file-mac
"""
filename = 'Picture.jpg'
ct,IV,tag,key,h,ext = MyfileEncryptMAC(filename)
filepath = 'Picture_Encr.jpg'
message = MyfileDecryptMAC(filepath,ct,IV,tag,key,h,ext)
"""
#test myencryptMac/mydecryptMac
"""
key = os.urandom(32)
HMACKey = os.urandom(32)
message = (b"Testing, testing, 1,2,3")
ct,IV,tag = MyEncryptMAC(message,key,HMACKey)
print(ct)
message2 = MyDecryptMAC(ct,IV,key,tag,HMACKey)
print(message2)
"""


"""filename = 'Picture.jpg'
RSAcipher,ct,IV,ext = MyRSAEncrypt(filename,'public_key.pem')
filename=Path(filename).stem +"_Encr"+ ext
MyRSADecrypt(RSAcipher,ct,IV,filename,ext,'private_key.pem')
 """

"""filename = 'Picture.jpg'
cipher,IV, key, ext = MyfileEncrypt(filename)
filename=Path(filename).stem +"_Encr"+ ext
MyfileDecrypt(filename, cipher, IV,key, ext)"""