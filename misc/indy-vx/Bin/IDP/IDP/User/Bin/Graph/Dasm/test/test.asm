; \IDP\Public\User\Bin\Graph\Dasm\Test\Test.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	include \masm32\include\kernel32.inc
	
	includelib \masm32\lib\kernel32.lib
	
BREAK macro
	int 3
endm

.code
	include ..\Dasm.inc
	include ..\Cookie\Cookie.asm
	
GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

_$_GetCallbackReference::
	pop eax
	ret

.data	; Static!
OpCount	ULONG ?

.code
_$_ParseCallback:
	GET_CURRENT_GRAPH_ENTRY
ParseCallback proc GraphEntry:PVOID, Instruction:PVOID, CallbackParameter:PVOID
	inc OpCount
	xor eax,eax
	ret
ParseCallback endp

.data
NtCookie	BLOCK_HEADER <<HEADER_TYPE_LINE, NULL>, NULL, 0, 1, 0>

.code
_$_SearchCallback:
	GET_CURRENT_GRAPH_ENTRY
SearchCallback proc Instruction:PVOID, CallbackParameter:PVOID, FirstSearch:BOOLEAN
	xor eax,eax
	mov ecx,Instruction
	.if FirstSearch
	.if NtCookie.Address == Ecx
	lea eax,NtCookie
	.endif
	.endif
	ret
SearchCallback endp

Entry proc
Local Buffer:PVOID, BufferHandle:HANDLE
Local Hash[2]:DWORD
	lea eax,Hash
	xor ecx,ecx
	mov dword ptr [Hash],0A1D45974H	; CRC32("RtlAllocateHeap")
	mov dword ptr [Hash + 4],ecx
	push eax
	push eax
	push ecx
	push ecx
	mov eax,MI_QUERY_ENTRIES
	Call GCBE
	test eax,eax
	jnz Exit
	invoke NtQuerySecurityCheckCookieReference, addr NtCookie.Address
	test eax,eax
	jnz Exit
; Инициализация менеджера буферов.
	mov eax,MM_INITIALIZE
	Call GCBE
	test eax,eax
	lea ecx,BufferHandle
	lea edx,Buffer
	jnz Exit
	push ecx
	push edx
	push eax	; Global.
	push PAGE_SIZE*1000H	; 16M
; Создаём расширяемый буфер.
	mov eax,MM_ALLOCATE_BUFFER
	Call GCBE
	test eax,eax
	mov ebx,Buffer
	jnz Error
	push eax	; SearchCallbackParameter
	lea ecx,Buffer
	push eax	; SearchCallbackRoutine
	push eax	; ParseCallbackParameter
	push eax	; ParseCallbackRoutine
	push eax	; LastIp
	push GP_PARSE_DISCLOSURE
	Call _$_ParseCallback
	push ecx
	mov dword ptr [esp + 3*4],eax
	Call _$_SearchCallback
	push dword ptr [Hash]	; RtlAllocateHeap()
	mov dword ptr [esp + 6*4],eax
;
; Парсинг процедуры с раскрытием вложенных процедур.
;
; Analyze:
; o P4, 3014MHz
; o 5.1.2600.5755
;
; o ntdll!_security_check_cookie()
; o 43388 IPs
; o ~2 Sec
; o ~119 KB
; o ~20 IP/ms
;
; o ntdll!RtlAllocateHeap()
; o 24193 IPs
; o ~0.67 Sec
; o ~64 KB
; o ~60 IP/ms
;
  invoke GetTickCount	; Import!
  mov ebx,eax
	mov eax,GP_PARSE
	Call GCBE
	test eax,eax
	jnz Free
  invoke GetTickCount
  sub eax,ebx
	BREAK
Free:
	push eax
; Освобождаем буфер.
	push BufferHandle
	mov eax,MM_FREE_BUFFER
	Call GCBE
	pop eax
Error:
	push eax
; Деинициализация менеджера.
	mov eax,MM_UNINITIALIZE
	Call GCBE
	pop eax
Exit:
	ret
Entry endp
end Entry