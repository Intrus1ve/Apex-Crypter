; o GCBE
; o U/K, MI
; o (c) Indy, 2011.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib

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
GCBE::
; GPE apps.
	test eax,eax
	jz QueryOpcodeSize
	dec eax
	jz QueryPrefixLength
	dec eax
	jz GpParse
	dec eax
	jz GpTrace
	dec eax
	jz RwConvertRawTableToCrossTable
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
	dec eax
; GCBE service.
	jz GpBuildGraph
	dec eax
	jz GpSwitchThread
	dec eax
	jz RedirectAllBranchLinks
	dec eax
	jz RwUnlinkEntry
	dec eax
	jz RwInsertHeadEntry
	mov eax,STATUS_ILLEGAL_FUNCTION
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
	lea esp,[esp + 2*4]
	pop ebp
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
	include GrpLink.asm
	include GrpSnap.asm
	include GrpJcx.asm
	include GrpIdle.asm
	include GrpCross.asm
	include GrpBuild.asm
	include GrpSwitch.asm

end GCBE