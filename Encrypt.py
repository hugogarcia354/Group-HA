import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path

def Myencrypt(message, key):
	if(len(key) < 32):
		return "The key is too short", "The key is too short"
	backend = default_backend()
	IV = os.urandom(16)
	padder = padding.PKCS7(128).padder()
	message = padder.update(message)
	message += padder.finalize()
	c =  Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	encryptor = c.encryptor()
	ct = encryptor.update(message) + encryptor.finalize()
	return ct, IV

def Mydecrypt(cipher, key, iv):
	backend = default_backend()
	c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = c.decryptor()
	message = decryptor.update(cipher) + decryptor.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	message = unpadder.update(message)
	message = message + unpadder.finalize()
	return message

def MyfileEncrypt(filepath):
	ext = os.path.splitext(filepath)
	ext = ext[1]
	if(ext == '.txt'):
		f = open(filepath, 'r')
		content = f.read()
		content = content.encode()
		filepath = 'fooE.txt'
	else:
		f = open(filepath, 'rb')
		content = f.read()
		filepath = 'fooE.jpg'
	f.close()
	key = os.urandom(32)
	write, iv = Myencrypt(content, key)
	f = open(filepath, 'wb')
	f.write(write)
	f.close()
	return write, key, iv, ext, filepath

def MyfileDecrypt(filepath, cipher, key, iv, ext):
	f = open(filepath, 'rb')
	content = f.read()
	f.close()
	message = Mydecrypt(content, key, iv)
	if( ext == '.txt'):
		message = message.decode()
		f = open('fooD.txt', 'w')
		f.write(message)
		f.close()
	else:
		f = open('fooD.jpg', 'wb')
		f.write(message)
		f.close()
	return message


cipher, Key, IV, ext, filename = MyfileEncrypt('Picture.jpg')
ogmessage = MyfileDecrypt(filename, cipher, Key, IV, ext)
