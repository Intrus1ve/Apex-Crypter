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
GPE::
	test eax,eax
	jz QueryOpcodeSize
	dec eax
	jz QueryPrefixLength
	dec eax
	jz GpParse
	dec eax
	jz GpTrace
	dec eax
	jz GpFastCheckIpBelongToSnapshot
	dec eax
	jz GpCheckIpBelongToSnapshot
	dec eax
	jz GpFindCallerBelongToSnapshot
	dec eax
	jz GpSearchRoutineEntry
	dec eax
	jz GpQueryRoutineArgsNumber
	mov eax,STATUS_INVALID_PARAMETER
	ret
	
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

	include VirXasm32b.asm
	
	include GrpParse.asm
	include GrpTrace.asm
	include GrpSnap.asm

end GPE
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

GCBE_PARSE_NL_UNLIMITED	equ -1

%NTERR macro
	.if Eax
	Int 3
	.endif
endm

%APIERR macro
	.if !Eax
	Int 3
	.endif
endm

.code
TestRoutine:
	nop
	nop
	nop
	jnz l1
	nop
	Call TT1
	nop
	jz l2
	nop
	Call TT2
	nop
	ret
l1:
	nop
l2:
	nop
	nop
	ret
	
TT1:
	nop
	nop
	jz l3
	nop
	Call TT3
	nop
	jnz l3
	nop
l3:
	ret

TT2:
	nop
	Call eax
	nop
	ret
	
TT3:
	nop
	ret

PARSE_CALLBACK_ROUTINE proc Graph:PVOID,	; Ссылка на граф.
 GraphEntry:PVOID,	; Ссылка на описатель инструкции.
 SubsList:PVOID,	; Список описателей входов процедур в порядке вызова.
 SubsCount:ULONG,	; Число процедур в списке является уровнем вложенности(NL).
 PreOrPost:BOOLEAN,	; Тип вызова.
 Context:PVOID
	xor eax,eax
	ret
PARSE_CALLBACK_ROUTINE endp

	assume fs:nothing
Ep proc
Local GpSize:ULONG
Local Snapshot:GP_SNAPSHOT
Local OldProtect:ULONG
	mov Snapshot.GpBase,NULL
	mov GpSize,1000H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr Snapshot.GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	mov ebx,Snapshot.GpBase
	%NTERR
	add Snapshot.GpBase,0FFFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr Snapshot.GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov Snapshot.GpLimit,ebx
	mov Snapshot.GpBase,ebx
	lea ecx,Snapshot.GpLimit
	push eax
	push eax
	push 1234H
	push offset PARSE_CALLBACK_ROUTINE
	push eax
	push GCBE_PARSE_NL_UNLIMITED
	push GCBE_PARSE_SEPARATE or GCBE_PARSE_OPENLIST
	push ecx
	push offset GPE
	mov eax,2
	Call GPE
	%NTERR
	
	xor ebx,ebx
	mov esi,Snapshot.GpBase
@@:
	test dword ptr [esi + EhEntryType],TYPE_MASK
	.if Zero?		; Line
	add ebx,dword ptr [esi + EhSize]
	.else
	push dword ptr [esi + EhAddress]
	call QueryOpcodeSize
	add ebx,eax
	.endif
	add esi,ENTRY_HEADER_SIZE
	cmp Snapshot.GpLimit,esi
	ja @b
	ret
Ep endp
end Ep