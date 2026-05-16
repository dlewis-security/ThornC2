import base64
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from Crypto.Cipher import AES
from Crypto.Util import Padding

class Crypto():
	def enc(plaintext):
		key = b'{{KEY}}'
		iv = b'{{IV}}'
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = Padding.pad(plaintext.encode(), AES.block_size)
		ciphertext =  cipher.encrypt(plaintext)
		ciphertext = base64.b64encode(ciphertext)
		return ciphertext

	def dec(ciphertext):
		key = b'{{KEY}}'
		iv = b'{{IV}}'
		cipher = AES.new(key, AES.MODE_CBC, iv)
		ciphertext = base64.b64decode(ciphertext)
		plaintext = cipher.decrypt(ciphertext)
		plaintext = Padding.unpad(plaintext, AES.block_size)
		return plaintext
