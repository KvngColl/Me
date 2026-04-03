@echo off
setlocal EnableExtensions

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=llama.jpg"

if /I "%~1"=="/h" goto :usage
if /I "%~1"=="-h" goto :usage
if /I "%~1"=="/?" goto :usage

if not exist "%TARGET%" (
  echo [keys] file not found: %TARGET%
  echo [keys] usage: keys [path-to-llama.jpg]
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$p = [System.IO.Path]::GetFullPath('%TARGET%');" ^
  "$bytes = [System.IO.File]::ReadAllBytes($p);" ^
  "$sha = [System.Security.Cryptography.SHA256]::Create();" ^
  "$digest = $sha.ComputeHash($bytes);" ^
  "$out = New-Object System.Text.StringBuilder;" ^
  "for($i=0;$i -lt 12;$i++){" ^
    "$mixed = $digest[$i] -bxor (($i * 0x2d + 0x41) -band 0xff);" ^
    "[void]$out.Append($mixed.ToString('x2'));" ^
  "}" ^
  "Write-Output ($out.ToString())"

if errorlevel 1 (
  echo [keys] token generation failed.
  exit /b 1
)

exit /b 0

:usage
echo keys - bootstrap token generator
echo.
echo Usage:
echo   keys
echo   keys path\to\llama.jpg
exit /b 0