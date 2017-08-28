# PowerLessShell

*PowerLessShell uses MSBuild.exe to execute PowerShell scripts and commands or raw shellcode without spawning powershell.exe.*

*This is a fork from https://github.com/Mr-Un1k0d3r/PowerLessShell. This fork contains documentation changes and payload and various functionality enhancements.*

### How it works

PowerLessShell reads in the desired input file, encrypts it with RC4 and then base64 encodes it. After this an msbuild project template is populated with the payload and key to decrypt it. The rest of the magic is taken care of by the csproj template created by [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r/PowerLessShell) which uses MSBuild's capability of running inline tasks in build files to execute the necessary code. 

#### Templates

Templates are located in the repo under PowerLessShell/include:

- template-powershell.csproj
- template-shellcode.csproj

The script obfuscates variables from the template. Variables should be named with VAR + a number (i.e. "VAR1").



## Usage

### Example

Generate shellcode with Cobalt Strike, using `Attacks > Packages > Payload Generator` or for a stageless payload use `Attacks > Packages > Windows Executable (S)` select "Raw" and save the file somewhere convenient.

Alternatively you can supply an arbitrary PowerShell script to be run instead of shellcode. Generate or obtain these the usual ways.

```
$ python PowerLessShell.py


PowerLessShell - Remain Stealthu
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

(Path to the raw shellcode file)>>> shellcode.bin

(Path for the generated MsBuild out file)>>> payload.csproj

(Set USERDOMAIN condition (Default ''))>>> RingZer0

(Use known process name to perform MsBuild renaming (Default: False))>>>

[+] payload.csproj was generated.
[+] payload.csproj.cmd was generated.
[+] Run the command inside of payload.csproj.cmd on the target system using WMI.
```

**Notes:**
- In order to prevent the payload from running in an analysis environment the USERDOMAIN condition create a check to see if the user's domain matches the one provided before executing the payload. This is an optional parameter.
- Known process name will cause the msbuild.exe to be renamed to something like WINWORD.exe instead of a randomly generated string (see code for exact list of names).



## Screenshot

The following example is running the RC4 RAT https://github.com/Mr-Un1k0d3r/RC4-PowerShell-RAT without running a single instance of PowerShell

![PowerLessShell](https://ringzer0team.com/powershellless.png)



## MSBuild conditions

MSBuild conditions can be used to avoid running code in unintended (read: analysis) environments.

```
<Target Name="x" Condition="'$(USERDOMAIN)'=='RingZer0'">
```

The malicious code will only be executed if the current domain is "RingZer0"

Several conditions can be used to create more thorough execution check, for example:

```
<Target Name="x" Condition="'$(registry:HKEY_LOCAL_MACHINE\blah@blah)'>='0'">
```

See the following for more information:

- [MSBuild Conditions](https://msdn.microsoft.com/en-us/library/7szfhaft.aspx)
- [Property Functions](https://docs.microsoft.com/en-us/visualstudio/msbuild/property-functions).



## Cobalt Strike Aggressor script (wmi_msbuild.cna)

**By MrT-F**

cd into your cobalt strike client directory
```
cd /root/cobaltstrike
```
Clone this repository into folder PowerLessShell
```
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git
```
Load the aggressor script in your Cobalt Strike Console
Laterally move just like other Cobalt Strike macros:
```
wmi_msbuild [target] [listener]
```



## Credit

Mr.Un1k0d3r RingZer0 Team 2017

