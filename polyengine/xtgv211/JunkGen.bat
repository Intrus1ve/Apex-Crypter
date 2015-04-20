@echo	off
C:\masm32\bin\ml.exe /c /coff /nologo /I C:\masm32\include JunkGen.asm
C:\masm32\bin\link.exe /subsystem:windows /DLL  /DEF:JunkGen.def /section:.text,RWE /nologo JunkGen.obj /libpath:C:\masm32\lib
:0 
del		JunkGen.obj
if		exist JunkGen.obj goto 0 
pause
cls
 