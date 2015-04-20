.386 
.model flat, stdcall
option casemap:none

include windows.inc

include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

JRET STRUCT
   ep dd 0
   sz dd 0
   data_addr dd 0
JRET ENDS

.data
xtg_data_struct_buf			db		1000h	dup	(00)
faka_fakeapi_gen_buf		db		1000h	dup	(00) 
xtg_func_struct_buf			db		1000h	dup	(00)
func_buf					db		1000h	dup (00)
xtg_trash_gen_buf			db		1000h	dup	(00)
rdata_buf					db		1000h	dup	(00)
rd_size						equ		$ - rdata_buf - 1
xdata_buf					db		1000h	dup	(00)
xd_size						equ		$ - xdata_buf - 1
jrt_buf						db		1000h	dup (00)					
trash_code_buf				db		5000h	dup	(00)
tcb_size					equ		$ - trash_code_buf - 10h


path_buf					db		1000h	dup	(00)
pb_size						equ		$ - path_buf - 1

path1						db	'JunkCode.bin', 0
numwrite					dd 0
len_buf						dd 0
buf_addr					dd 0
data_address				dd 0

.code

engines:
include		rang32.asm													
include		xtg.inc	
include		xtg.asm
include		faka.asm
include		logic.asm
include		irpe.asm

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

GenJunk proc CodeLength:DWORD, XMASK:DWORD, FREGS:DWORD, BDATA:DWORD, DATA_ADDR:DWORD, DATA_SIZE:DWORD

	lea ecx, xtg_trash_gen_buf
	assume ecx: ptr XTG_TRASH_GEN

	;RNG
	mov [ecx].rang_addr, RANG32
	
	; Fake WinAPI
	mov [ecx].faka_addr, 0

	;Func
	mov [ecx].xfunc_struct_addr, 0
	
	mov [ecx].alloc_addr, xVirtualAlloc
	mov [ecx].free_addr, xVirtualFree

	; Fake Data
	mov [ecx].xdata_struct_addr, 0

	;FAKE DATA
	mov eax, BDATA
	test eax, eax
	je cont

	fake_data:
	lea edx, xtg_data_struct_buf
	mov [ecx].xdata_struct_addr, edx
	assume edx: ptr XTG_DATA_STRUCT
	mov [edx].xmask, XTG_DG_ON_XMASK

	push DATA_SIZE
	call [ecx].alloc_addr

	push DATA_SIZE													;size
	push eax														;addr
	call xmemset

	mov [edx].rdata_addr, eax
	mov [data_address], eax

	mov eax, DATA_SIZE
	mov [edx].rdata_size, eax
	mov [edx].rdata_pva, XTG_VIRTUAL_ADDR

	mov eax, DATA_ADDR
	mov [edx].xdata_addr, eax
	mov eax, DATA_SIZE
	mov [edx].xdata_size, eax

	cont:

	push CodeLength
	call [ecx].alloc_addr

	mov edi, eax

	push CodeLength													;size
	push edi														;addr
	call xmemset

	mov eax, edi

	;lea eax, trash_code_buf
	mov [ecx].tw_trash_addr, eax

	mov edx, CodeLength
	mov [ecx].trash_size, edx

	mov [ecx].fmode, XTG_REALISTIC
	mov eax, XMASK
	mov [ecx].xmask1, eax
	mov [ecx].xmask2, 0
	mov eax, FREGS
	mov [ecx].fregs, eax

	push ecx
	call xTG
	
	pushad
	
	push 12
	call [ecx].alloc_addr

	assume eax: ptr JRET

	mov ebx, [data_address]
	mov [eax].data_addr, ebx

	mov ebx, [ecx].fnw_addr
	mov edx, [ecx].ep_trash_addr
	sub ebx, edx
	mov [eax].sz, ebx

	mov ebx, [ecx].ep_trash_addr
	mov [eax].ep, ebx

	mov [esp + 28], eax

	popad

	ret

	;pushad
	;mov eax, [ecx].nobw
	;mov len_buf, eax
	;mov eax, [ecx].ep_trash_addr
	;mov buf_addr, eax
	;mov eax, [ecx].fnw_addr

	;mov eax, [ecx].fnw_addr
	;mov ebx, [ecx].ep_trash_addr
	;sub eax, ebx
	;mov MaxCodeLength, eax

	;push 0
	;push 80h
	;push 2
	;push 0
	;push 0
	;push GENERIC_WRITE
	;lea ecx, path1
	;push ecx
	;call CreateFileA

	;eax = handle_file
	;mov edi, eax

	;push 0 ;Overlapped
	;lea edx, numwrite
	;push edx ; &numbyteswritten
	;mov ebx, MaxCodeLength
	;push ebx ;numbytestowrite
	;push buf_addr ;addr
	;push edi ;hFile
	;call WriteFile

	;push edi
	;call CloseHandle

	;popad
	;ret

GenJunk endp

GenJunkFPU proc CodeLength:DWORD

	lea ecx, xtg_trash_gen_buf
	assume ecx: ptr XTG_TRASH_GEN

	;RNG
	mov [ecx].rang_addr, RANG32
	
	; Fake WinAPI
	mov [ecx].faka_addr, 0

	;Func
	mov [ecx].xfunc_struct_addr, 0
	
	mov [ecx].alloc_addr, xVirtualAlloc
	mov [ecx].free_addr, xVirtualFree

	; Fake Data
	mov [ecx].xdata_struct_addr, 0

	push CodeLength
	call [ecx].alloc_addr

	mov edi, eax

	push CodeLength													;size
	push edi														;addr
	call xmemset

	mov eax, edi

	;lea eax, trash_code_buf
	mov [ecx].tw_trash_addr, eax

	mov edx, CodeLength
	mov [ecx].trash_size, edx

	mov [ecx].fmode, XTG_MASK
	mov [ecx].xmask1, 0
	mov [ecx].xmask2, XTG_XFPU
	mov eax, 0
	mov [ecx].fregs, eax

	push ecx
	call xTG
	
	pushad
	
	push 12
	call [ecx].alloc_addr

	assume eax: ptr JRET

	mov [eax].data_addr, 0

	mov ebx, [ecx].fnw_addr
	mov edx, [ecx].ep_trash_addr
	sub ebx, edx
	mov [eax].sz, ebx

	mov ebx, [ecx].ep_trash_addr
	mov [eax].ep, ebx

	mov [esp + 28], eax

	popad

	ret

GenJunkFPU endp


End LibMain