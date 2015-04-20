@echo off
set EXE=gen
ECHO ====================================
ECHO               DEBUG MODE
ECHO ====================================
if not exist rsrc.rc goto over1
\masm32\bin\rc /v rsrc.rc
\masm32\bin\cvtres /machine:ix86 rsrc.res
 :over1
 
if exist "%EXE%.obj" del "%EXE%.obj"
if exist "%EXE%.exe" del "%EXE%.exe"

\masm32\bin\ml  /Cp /Zi /c /coff /Zd /Zf /nologo  "%EXE%.asm" 
if errorlevel 1 goto errasm

if not exist rsrc.obj goto nores

\masm32\bin\Link /SUBSYSTEM:console /NOLOGO /DEBUG /DEBUGTYPE:COFF  "%EXE%.obj"  rsrc.res /ALIGN:16  /SECTION:codes,RWE /VERSION:0.666 /PDB:"%EXE%.pdb"
 if errorlevel 1 goto errlink


goto TheEnd_debug

:nores
 \masm32\bin\Link /SUBSYSTEM:console "%EXE%.obj" /ALIGN:16  /NOLOGO  /SECTION:codes,RWE /VERSION:0.666  /debug  /ENTRY:code /PDB:"%EXE%.pdb"

goto TheEnd_debug

:errlink
 echo _
echo Link error
goto TheEnd

:errasm
 echo _
echo Assembly Error
goto TheEnd

:TheEnd
 
pause
:TheEnd_debug

if exist "%EXE%.obj" del "%EXE%.obj"
if exist "%EXE%.ilk" del "%EXE%.ilk"
echo if exist "%EXE%.pdb" del "%EXE%.pdb"
pause

