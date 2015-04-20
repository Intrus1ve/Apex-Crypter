	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

%GET_CURRENT_GRAPH_ENTRY macro
	Call GetGraphReference
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GetGraphReference::
	pop eax
	ret
endm
.code
	jmp MsgBox
	
	%GET_GRAPH_REFERENCE

	assume fs:nothing
SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[0]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	%GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov ecx,dword ptr [esp + 3*4]	; Ctx.
	mov edx,dword ptr [esp]	; ~ nt!ExecuteHandler2().
	mov ebx,CONTEXT.regEbx[ecx]
	mov esi,CONTEXT.regEsi[ecx]
	mov edi,CONTEXT.regEdi[ecx]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov ecx,EXCEPTION_RECORD.ExceptionAddress[eax]
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

	include Img.asm

MsgBox proc
Local Entries[4]:PVOID
Local DllNameU:UNICODE_STRING
Local $DllName[3*4]:CHAR
Local DllHandle:HANDLE
Local $Title[4]:CHAR
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov Entries[0],059B88A67H	; HASH("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],0DB164279H	; HASH("RtlFreeUnicodeString")
	mov Entries[2*4],09E1E35CEH	; HASH("LdrLoadDll")
	mov Entries[3*4],NULL
	invoke LdrEncodeEntriesList, Ebx, 0, addr Entries
	test eax,eax
	lea ecx,DllNameU
	lea edx,$DllName
	jnz Exit
	mov dword ptr $DllName[0],"resU"
	mov dword ptr $DllName[4],"d.23"
	mov dword ptr $DllName[2*4],"ll"
	push edx
	push ecx
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,DllNameU
	lea edx,DllHandle
	.if Zero?
	   mov eax,STATUS_INTERNAL_ERROR
	   jmp Exit
	.endif
	push edx
	push ecx
	push NULL
	push NULL
	Call Entries[2*4]	; LdrLoadDll()
	lea ecx,DllNameU
	push eax
	push ecx
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	test eax,eax
	mov Entries[0],5B9E46FEH	; HASH("MessageBoxA")
	mov Entries[4],eax
	jnz Exit
	invoke LdrEncodeEntriesList, DllHandle, 0, addr Entries
	test eax,eax
	lea ecx,$DllName
	lea edx,$Title
	jnz Exit
	mov dword ptr [$Title],".."
	push MB_OK
	push edx
	push ecx
	push eax
	Call Entries[0]
	xor eax,eax
Exit:
	ret
MsgBox endp
end MsgBox