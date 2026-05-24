@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Windows classic BAT wrapper. All body and plaintext values are lowercase hex.
rem Usage:
rem   yint.bat derive MASTER_HEX
rem   yint.bat build-request MASTER_HEX METHOD URI PLAINTEXT_HEX
rem   yint.bat open-request MASTER_HEX METHOD URI TIMESTAMP NONCE SIGN BODY_HEX [TIME_WINDOW] [NONCE_FILE]
rem   yint.bat build-response MASTER_HEX STATUS REQ_NONCE PLAINTEXT_HEX
rem   yint.bat open-response MASTER_HEX STATUS REQ_NONCE TIMESTAMP NONCE SIGN BODY_HEX [TIME_WINDOW]

if not defined YINT_CORE set "YINT_CORE=%~dp0..\..\core\bin\yint.exe"
if not exist "%YINT_CORE%" set "YINT_CORE=%~dp0..\..\core\bin\yint"
if not defined YINT_TIME_WINDOW set "YINT_TIME_WINDOW=300"
if not defined YINT_NONCE_FILE set "YINT_NONCE_FILE=%TEMP%\yint-nonces.txt"

set "CMD=%~1"
shift /1
if /I "%CMD%"=="derive" goto :derive
if /I "%CMD%"=="build-request" goto :build_request
if /I "%CMD%"=="open-request" goto :open_request
if /I "%CMD%"=="build-response" goto :build_response
if /I "%CMD%"=="open-response" goto :open_response
echo usage: yint.bat derive^|build-request^|open-request^|build-response^|open-response ... 1>&2
exit /b 2

:now
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "[int64](([DateTime]::UtcNow - [DateTime]'1970-01-01T00:00:00Z').TotalSeconds)"`) do set "YINT_NOW=%%T"
exit /b 0

:keys
for /f "tokens=1,2" %%A in ('"%YINT_CORE%" derive "%~1"') do (
  set "K_ENC=%%A"
  set "K_MAC=%%B"
)
if not defined K_ENC exit /b 1
if not defined K_MAC exit /b 1
exit /b 0

:derive
"%YINT_CORE%" derive "%~1"
exit /b %ERRORLEVEL%

:build_request
set "MASTER=%~1"
set "METHOD=%~2"
set "URI=%~3"
set "PLAIN=%~4"
call :keys "%MASTER%" || exit /b 1
call :now
for /f "delims=" %%A in ('"%YINT_CORE%" random 16') do set "NONCE=%%A"
for /f "delims=" %%A in ('"%YINT_CORE%" random 16') do set "IV=%%A"
for /f "delims=" %%A in ('echo|set /p=!PLAIN!^| "%YINT_CORE%" build-body "!K_ENC!" "!IV!" -') do set "BODY=%%A"
for /f "delims=" %%A in ('echo|set /p=!BODY!^| "%YINT_CORE%" sign-req "!K_MAC!" "!METHOD!" "!URI!" "!YINT_NOW!" "!NONCE!" -') do set "SIGN=%%A"
echo timestamp=!YINT_NOW!
echo nonce=!NONCE!
echo sign=!SIGN!
echo body_hex=!BODY!
exit /b 0

:cleanup_nonce_file
set "NOW=%~1"
set "FILE=%~2"
if not exist "%FILE%" type nul > "%FILE%"
set "TMP=%FILE%.%RANDOM%.tmp"
type nul > "%TMP%"
for /f "tokens=1,2" %%A in (%FILE%) do (
  if %%B GEQ %NOW% echo %%A %%B>>"%TMP%"
)
move /y "%TMP%" "%FILE%" > nul
exit /b 0

:nonce_seen
set "SEEN=0"
if exist "%~2" (
  findstr /b /c:"%~1 " "%~2" > nul && set "SEEN=1"
)
exit /b 0

:open_request
set "MASTER=%~1"
set "METHOD=%~2"
set "URI=%~3"
set "TS=%~4"
set "NONCE=%~5"
set "SIGN=%~6"
set "BODY=%~7"
set "WINDOW=%~8"
set "NONCE_FILE=%~9"
if not defined WINDOW set "WINDOW=%YINT_TIME_WINDOW%"
if not defined NONCE_FILE set "NONCE_FILE=%YINT_NONCE_FILE%"
call :keys "%MASTER%" || exit /b 1
call :now
set /a "DELTA=YINT_NOW-TS"
if !DELTA! LSS 0 set /a "DELTA=0-DELTA"
if !DELTA! GTR %WINDOW% echo unauthorized 1>&2 & exit /b 145
call :cleanup_nonce_file "!YINT_NOW!" "!NONCE_FILE!"
call :nonce_seen "!NONCE!" "!NONCE_FILE!"
if "!SEEN!"=="1" echo unauthorized 1>&2 & exit /b 145
for /f "delims=" %%A in ('echo|set /p=!BODY!^| "%YINT_CORE%" verify-req "!K_MAC!" "!METHOD!" "!URI!" "!TS!" "!NONCE!" "!SIGN!" - 2^>nul') do set "VERIFY=%%A"
if not "!VERIFY!"=="OK" echo unauthorized 1>&2 & exit /b 145
set /a "EXPIRE=TS+WINDOW"
echo !NONCE! !EXPIRE!>>"!NONCE_FILE!"
echo|set /p=!BODY!| "%YINT_CORE%" decrypt-body "!K_ENC!" -
exit /b %ERRORLEVEL%

:build_response
set "MASTER=%~1"
set "STATUS_CODE=%~2"
set "REQ_NONCE=%~3"
set "PLAIN=%~4"
call :keys "%MASTER%" || exit /b 1
call :now
for /f "delims=" %%A in ('"%YINT_CORE%" random 16') do set "NONCE=%%A"
for /f "delims=" %%A in ('"%YINT_CORE%" random 16') do set "IV=%%A"
for /f "delims=" %%A in ('echo|set /p=!PLAIN!^| "%YINT_CORE%" build-body "!K_ENC!" "!IV!" -') do set "BODY=%%A"
for /f "delims=" %%A in ('echo|set /p=!BODY!^| "%YINT_CORE%" sign-resp "!K_MAC!" "!STATUS_CODE!" "!YINT_NOW!" "!NONCE!" "!REQ_NONCE!" -') do set "SIGN=%%A"
echo timestamp=!YINT_NOW!
echo nonce=!NONCE!
echo sign=!SIGN!
echo body_hex=!BODY!
exit /b 0

:open_response
set "MASTER=%~1"
set "STATUS_CODE=%~2"
set "REQ_NONCE=%~3"
set "TS=%~4"
set "NONCE=%~5"
set "SIGN=%~6"
set "BODY=%~7"
set "WINDOW=%~8"
if not defined WINDOW set "WINDOW=%YINT_TIME_WINDOW%"
call :keys "%MASTER%" || exit /b 1
call :now
set /a "DELTA=YINT_NOW-TS"
if !DELTA! LSS 0 set /a "DELTA=0-DELTA"
if !DELTA! GTR %WINDOW% echo unauthorized 1>&2 & exit /b 145
for /f "delims=" %%A in ('echo|set /p=!BODY!^| "%YINT_CORE%" verify-resp "!K_MAC!" "!STATUS_CODE!" "!TS!" "!NONCE!" "!REQ_NONCE!" "!SIGN!" - 2^>nul') do set "VERIFY=%%A"
if not "!VERIFY!"=="OK" echo unauthorized 1>&2 & exit /b 145
echo|set /p=!BODY!| "%YINT_CORE%" decrypt-body "!K_ENC!" -
exit /b %ERRORLEVEL%
