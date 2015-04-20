Dos2Optional proc dos:dword
mov eax, dos
	assume eax:ptr IMAGE_DOS_HEADER 
add eax, [eax].e_lfanew
	assume eax:ptr IMAGE_NT_HEADERS
add eax,sizeof IMAGE_FILE_HEADER+4
ret
Dos2Optional endp

GetSection_SizeOfRawData proc  SectionAddr:dword
assume eax:ptr IMAGE_SECTION_HEADER
mov eax,SectionAddr
mov eax,[eax].SizeOfRawData
assume eax:nothing
ret
GetSection_SizeOfRawData endp

GetSectionAlignment proc dos:dword
invoke Dos2Optional,dos
assume eax:ptr IMAGE_OPTIONAL_HEADER
mov eax, [eax].SectionAlignment
assume eax:nothing
ret
GetSectionAlignment endp

GetSection_PointerToRawData proc current_section:dword
mov eax,current_section
assume eax:ptr IMAGE_SECTION_HEADER
mov eax, [eax].PointerToRawData
assume eax:nothing
ret
GetSection_PointerToRawData endp

GetNextSections proc dvar:dword
mov eax,dvar
add eax,sizeof IMAGE_SECTION_HEADER
ret
GetNextSections endp

Dos2FirstSection proc dos:dword
mov edi, dos
	assume edi:ptr IMAGE_DOS_HEADER
add edi, [edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
add edi,sizeof IMAGE_NT_HEADERS
mov eax,edi
ret
Dos2FirstSection endp

GetSectionByName proc dos,named
local names[9]:byte
invoke Dos2FirstSection,dos
@@:
lea ebx,names
invoke CopyBinZ,eax,ebx,8
push eax ; -> GetNextSections
invoke szCmps,named,addr names
	cmp eax,1
	je @end
call GetNextSections
	cmp dword ptr [eax],0
	je @err
jmp @B
@err:
mov eax,-1
ret
@end:
pop eax
ret
GetSectionByName endp




