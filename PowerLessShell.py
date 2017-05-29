# Author: Mr.Un1k0d3r - RingZer0 Team 2017

import random
import string
import base64
import sys
import re
import os

TEMPLATE = "template.csproj"

class Generator:

	def __init__(self, path):
		try:
			self.data = open(path, "rb").read()
		except:
			print "[-] %s not found." % path
			exit(0)
		self.rand_vars()
			
	def gen_str(self, size):
		return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size)) 

	def rand_vars(self):
		for i in reversed(range(1, 31)):
			self.data = self.data.replace("VAR" + str(i), self.gen_str(random.randrange(5, 25)))
			
	def get_output(self):
		return self.data
		
	def gen_rc4_key(self, size):
		return os.urandom(size)
		
	def format_rc4_key(self, key):
		return "0x" + ", 0x".join(re.findall("..", key.encode("hex")))
		
	def get_powershell(self, path):
		try:
			data = open(path, "rb").read()
		except:
			print "[-] %s not found." % path
			exit(0)	
		return data
	
class RC4:

	def KSA(self, key):
		keylength = len(key)

		S = range(256)

		j = 0
		for i in range(256):
			j = (j + S[i] + key[i % keylength]) % 256
			S[i], S[j] = S[j], S[i]

		return S


	def PRGA(self, S):
		i = 0
		j = 0
		while True:
			i = (i + 1) % 256
			j = (j + S[i]) % 256
			S[i], S[j] = S[j], S[i] 

			K = S[(S[i] + S[j]) % 256]
			yield K


	def Encrypt(self, plaintext, key):
		output = ""
		key = [ord(c) for c in key]
		S = self.KSA(key)
		keystream = self.PRGA(S)
		for c in plaintext:
			output = output + chr(ord(c) ^ keystream.next())
		return output	
		
if __name__ == "__main__":
	gen = Generator(TEMPLATE)
	rc4 = RC4()
	key = gen.gen_rc4_key(32)
	cipher = base64.b64encode(rc4.Encrypt(gen.get_powershell(sys.argv[1]), key))
	output = gen.get_output()
	output = output.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
	print output
