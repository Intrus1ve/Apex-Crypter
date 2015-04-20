	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

LdrSetDllManifestProber proto :dword
_imp__ZwResumeThread proto :dword, :dword
_imp__CreateProcessA proto :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword
	
.code GPECODE
	include ..\Bin\Gpe.inc

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

CR	equ 13
LF	equ 10

.data
StFlagsOffset	ULONG ?
StAddress		PVOID ?

.code
$Ch	CHAR "2nd'f called..", CR, LF, 0

Fn2ndDispatch proc C
	pushad
	invoke DbgPrint, addr $Ch
	popad
	jmp StAddress
Fn2ndDispatch endp

TbStackBase	equ 4
TbStackLimit	equ 8

$Ld	CHAR "SFC Frame: 0x%p", CR, LF, 0

	assume fs:nothing	
LdrpManifestProberRoutine proc DllBase:PVOID, FullDllPath:PCWSTR, ActivationContext:PVOID
	mov eax,STACK_FRAME.Next[ebp]
	mov ecx,StAddress
	assume eax:PSTACK_FRAME
@@:
	cmp eax,-1
	je @f
	cmp fs:[TbStackBase],eax
	jna @f
	cmp fs:[TbStackLimit],eax
	ja @f
	cmp [eax].Ip,ecx
	je Load
	mov eax,[eax].Next
	jmp @b
Load:
	mov ecx,StFlagsOffset
	mov [eax].Ip,offset Fn2ndDispatch
	or dword ptr [eax + ecx],CREATE_SUSPENDED
	invoke DbgPrint, addr $Ld, Eax
@@:
	xor eax,eax
	ret
LdrpManifestProberRoutine endp

; o !GCBE_PARSE_SEPARATE
; o !GCBE_PARSE_OPENLIST
;
PARSE_CALLBACK_ROUTINE proc uses ebx Graph:PVOID,	; Ссылка на граф.
 GraphEntry:PVOID,	; Ссылка на описатель инструкции.
 SubsList:PVOID,	; Список описателей входов процедур в порядке вызова.
 SubsCount:ULONG,	; Число процедур в списке является уровнем вложенности(NL).
 PreOrPost:BOOLEAN,	; Тип вызова.
 Context:PVOID
; Def. Flags offset.
	mov ebx,GraphEntry
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_CALL
	jne @f
; (!BRANCH_DEFINED_FLAG)
	mov eax,dword ptr [ebx + EhAddress]
	cmp word ptr [eax],15FFH
	jne @f
	mov eax,dword ptr [eax + 2]
	mov eax,dword ptr [eax]
	cmp dword ptr [_imp__ZwResumeThread],eax
	jne @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	test dword ptr [ebx + EhEntryType],TYPE_MASK
	jnz @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_JXX
	jne @f
	mov ebx,dword ptr [ebx + EhBlink]
	and ebx,NOT(TYPE_MASK)
	jz @f
	mov ebx,dword ptr [ebx + EhAddress]
	cmp byte ptr [ebx + 1],45H
	jne @f
	movzx eax,byte ptr [ebx]
	sub eax,0F6H
	jb @f
	.if Zero?
	movzx eax,byte ptr [ebx + 3]
	.else
	dec eax
	jnz @f
	mov eax,dword ptr [ebx + 3]
	.endif
	cmp eax,CREATE_SUSPENDED		; 4
	jne @f
	movzx eax,byte ptr [ebx + 2]
	cmp eax,4
	jna @f
	mov StFlagsOffset,eax
; Def. STACK_FRAME.Ip
	mov ecx,SubsList
	cmp SubsCount,2
	jb @f
	mov ecx,dword ptr [ecx]	; PCALL_HEADER
	mov ecx,dword ptr [ecx + EhFlink]
	and ecx,NOT(TYPE_MASK)
	jz @f
	mov ecx,dword ptr [ecx + EhAddress]
	mov eax,STATUS_WAIT_1
	mov StAddress,ecx
	jmp Exit
@@:
	xor eax,eax
Exit:
	ret
PARSE_CALLBACK_ROUTINE endp

$PsName	CHAR "d:\windows\system32\calc.exe",0

$Fn	CHAR "Ip: 0x%p, Flg: 0x%x", CR, LF, 0

Ep proc
Local Snapshot:GP_SNAPSHOT
Local GpSize:ULONG
Local OldProtect:ULONG
Local StartupInfo:STARTUPINFO
Local ProcessInfo:PROCESS_INFORMATION
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
	push 8
	push GCBE_PARSE_DISCLOSURE
	push ecx
	push dword ptr [_imp__CreateProcessA]
	%GPCALL GP_PARSE
	.if !Eax
	mov eax,STATUS_NOT_FOUND
	Int 3
	.elseif Eax != STATUS_WAIT_1
	Int 3
	.endif
	.if !StAddress
	Int 3
	.endif
	invoke DbgPrint, addr $Fn, StAddress, StFlagsOffset
	invoke LdrSetDllManifestProber, offset LdrpManifestProberRoutine
	invoke GetStartupInfo, addr StartupInfo
; !CREATE_SUSPENDED
	invoke CreateProcess, addr $PsName, NULL, NULL, NULL, FALSE, 0, NULL, NULL, addr StartupInfo, addr ProcessInfo
	%APIERR
	invoke Sleep, 3000
	invoke ZwResumeThread, ProcessInfo.ThreadHandle, NULL
	%NTERR
	ret
Ep endp
end Ep