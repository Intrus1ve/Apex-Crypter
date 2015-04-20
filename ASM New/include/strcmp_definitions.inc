%macro _strcmp 2
	push eax
	push ecx
	push edx
	push %1
	push %2
	call _strcmp@8
	pop edx
	pop ecx
	pop eax
%endmacro

%define STR_EQUAL byte 0
%define STR_INEQUAL  byte 255
%define strcmp(a,b) _strcmp dword a,dword b