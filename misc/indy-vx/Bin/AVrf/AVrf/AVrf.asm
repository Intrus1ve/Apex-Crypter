; o AV provider dll.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

include avrf.inc

.code
xNtAllocateVirtualMemory:
	nop
	jmp NtAllocateVirtualMemory

xNtFreeVirtualMemory:
	nop
	jmp NtFreeVirtualMemory

.data
Tnunk1	CHAR "NtAllocateVirtualMemory",0
Tnunk2	CHAR "NtFreeVirtualMemory",0
$DLL1	WCHAR "n","t","d","l","l",".","d","l","l",0

align 4
; RTL_VERIFIER_THUNK_DESCRIPTOR:
Dll1Thunks	dd Tnunk1
			dd 0
			dd xNtAllocateVirtualMemory
			
			dd Tnunk2
			dd 0
			dd xNtFreeVirtualMemory
			
			dd 0

; RTL_VERIFIER_DLL_DESCRIPTOR:
DLL1			dd $DLL1
			dd 0
			dd 0
			dd Dll1Thunks
			
			dd 0

; RTL_VERIFIER_PROVIDER_DESCRIPTOR:
Avrf			dd sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR)
			dd DLL1
			dd 0
			dd 0
			dd 0
			dd 0
.code
InitRoutine proc DllHandle:PVOID, Reason:ULONG, Context:PVOID
	.if Reason == DLL_PROCESS_VERIFIER
	mov eax,Context
	mov dword ptr [eax],offset Avrf
	.endif
	mov eax,TRUE
	ret
InitRoutine Endp
end InitRoutine