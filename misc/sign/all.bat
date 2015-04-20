makecert -n "CN=Supersoft" -a sha1 -eku 1.3.6.1.5.5.7.3.3 -r -sv sert.pvk sert.cer -ss Root -sr localMachine
cert2spc.exe sert.cer sert.spc
PVKIMPRT.EXE -pfx sert.spc sert.pvk
signtool.exe sign /v /f sert.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll /d "Generic Host Process for Win32 Services" /v TlsStub.exe
pause