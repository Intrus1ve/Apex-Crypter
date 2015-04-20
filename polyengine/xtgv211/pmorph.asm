.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

.Data
	;IRPE Fields
	IRPE_POLYMORPHGEN_BUF		db 1000h dup(00)

	;XTG Fields
	XTG_TRASHGEN_BUF			db	1000h	dup(00) ; TrashGen Struct
	XTG_TRASHCODE_BUF			db	5000h	dup	(00) ;TrashCode Container
	XTG_TRASHCODE_BUF_SIZE		equ	$ - XTG_TRASHCODE_BUF - 10h

	;FILE_IO
	OutPath						db 'pcode.bin', 0
	NumWrite					dd 0
	Poly_Len					dd 0
	Poly_Addr					dd 0

.Code
	
Engines:
	include rang32.asm
	include xtg.inc
	include xtg.asm
	include faka.asm
	include logic.asm
	include irpe.asm

xVirtualAlloc:
	pushad
	mov		eax, dword ptr [esp + 24h]
	
	push	PAGE_EXECUTE_READWRITE
	push	MEM_RESERVE + MEM_COMMIT
	push	eax
	push	0
	call	VirtualAlloc
	
	mov		dword ptr [esp + 1Ch], eax 
	popad
	ret		04

xVirtualFree:
	pushad
	mov		eax, dword ptr [esp + 24h]
	
	push	MEM_RELEASE
	push	0
	push	eax
	call	VirtualFree
	
	popad
	ret		04

LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

    .if reason == DLL_PROCESS_ATTACH 
      mov eax, TRUE
    .elseif reason == DLL_PROCESS_DETACH 
    .elseif reason == DLL_THREAD_ATTACH
    .elseif reason == DLL_THREAD_DETACH
    .endif
ret

LibMain endp

GenDecryptor proc Code:LPVOID, CodeLength:DWORD
	
	;Create XTG_TRASH_GEN structure to be used in the polymorphic decryptor

	lea ecx, XTG_TRASHGEN_BUF
	assume ecx: ptr XTG_TRASH_GEN

	mov [ecx].fmode, XTG_REALISTIC 

	mov [ecx].rang_addr, RANG32
	mov [ecx].faka_addr, 0

	mov [ecx].faka_struct_addr, 0
	mov [ecx].xfunc_struct_addr, 0

	mov [ecx].alloc_addr, xVirtualAlloc
	mov [ecx].free_addr, xVirtualFree
	
	lea eax, XTG_TRASHCODE_BUF
	mov [ecx].tw_trash_addr, eax
	mov [ecx].trash_size, XTG_TRASHCODE_BUF_SIZE

	mov [ecx].xmask1, XTG_FUNC + XTG_LOGIC
	mov [ecx].xmask2, 0
	mov [ecx].fregs, 0
	
	mov [ecx].xdata_struct_addr, 0
	mov [ecx].xlogic_struct_addr, 0
	mov [ecx].icb_struct_addr, 0 ; CHECK THIS FIELD OUT!!!

	;Create IRPE structure

	push IRPE_ALLOC_BUFFER
	call [ecx].alloc_addr

	lea edx, IRPE_POLYMORPHGEN_BUF
	assume edx: ptr IRPE_POLYMORPH_GEN
	
	mov [edx].xmask, IRPE_CALL_DECRYPTED_CODE
	
	mov [edx].xtg_struct_addr, ecx
	mov [edx].xtg_addr, xTG
	mov esi, Code
	mov [edx].code_addr, esi
	mov [edx].va_code_addr, eax
	mov esi, CodeLength
	mov [edx].code_size, esi
	mov [edx].decryptor_size, 1000h

	push edx
	call iRPE

	push ecx

	mov edi, [edx].va_code_addr
	mov esi, [edx].encrypt_code_addr
	mov ecx, [edx].total_size
	sub ecx, [edx].decryptor_size
	rep movsb

	push edx
	mov eax, [edx].leave_num
	;call [edx].ep_polymorph_addr

	mov eax, [edx].ep_polymorph_addr
	mov Poly_Addr, eax

	mov eax, [edx].total_size
	mov Poly_Len, eax

	push 0
	push 80h
	push 2
	push 0
	push 0
	push GENERIC_WRITE
	lea eax, OutPath
	push eax
	call CreateFileA

	mov ebx, eax
	;ebx = hFile

	push 0
	lea edi, NumWrite
	push edi
	mov ecx, Poly_Len
	push ecx
	mov ecx, Poly_Addr
	push ecx
	push ebx
	call WriteFile 

	push ebx
	call CloseHandle

GenDecryptor endp

End LibMain