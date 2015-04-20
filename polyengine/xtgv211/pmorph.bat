@echo	off
C:\masm32\bin\ml.exe /c /coff /nologo /I C:\masm32\include pmorph.asm
C:\masm32\bin\link.exe /subsystem:windows /DLL  /DEF:pmorph.def /section:.text,RWE /nologo pmorph.obj /libpath:C:\masm32\lib
:0 
del		pmorph.obj
if		exist pmorph.obj goto 0 
pause
cls
 