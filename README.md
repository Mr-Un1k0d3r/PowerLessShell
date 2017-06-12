# PowerLessShell

PowerLessShell rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawing powershell.exe

# Usage

Attacker side
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



(Path to the PowerShell script)>>> powershell.ps1

(Path for the generated MsBuild out file)>>> payload.csproj


[+] payload.csproj was generated.
[+] payload.csproj.cmd was generated.
[+] Run the command inside of payload.csproj.cmd on the target system using WMI.
```

# Example

The following example is running the RC4 RAT https://github.com/Mr-Un1k0d3r/RC4-PowerShell-RAT without running a single instance of PowerShell

![PowerLessShell](https://ringzer0team.com/powershellless.png)

# Cobalt Strike Aggressor script (wmi_msbuild.cna) By MrT-F

cd into your cobalt strike client directory
```
cd /root/cobaltstrike
```
Clone this repository into folder PowerLessShell
```
mkdir PowerLessShell
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell.git PowerLessShell
```
Load the aggressor script in your Cobalt Strike Console
Laterally move just like other Cobalt Strike macros:
```
wmi_msbuild [target] [listener]
```

# TODO 
* MsBuild renaming
* Delete payload
# Credit
Mr.Un1k0d3r RingZer0 Team 2017

