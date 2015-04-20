	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
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

	Public gChainDispatch
	Public gLoadLibraryArg
.data
gSnapshot			GP_SNAPSHOT <>
gChainDispatch		PVOID ?
gLoadLibraryArg	PSTR ?

.code
LoadLibrary2ndDispatch proc C
	pushad
	invoke DbgPrint, gLoadLibraryArg
	popad
	jmp gChainDispatch
LoadLibrary2ndDispatch endp
	
LdrpManifestProberRoutine proc DllBase:PVOID, FullDllPath:PCWSTR, ActivationContext:PVOID
Local Caller:GP_CALLER 
	lea eax,Caller
	push eax
	push UserMode
	push NULL
	push offset gSnapshot
	%GPCALL GP_FIND_CALLER_BELONG_TO_SNAPSHOT
	.if !Eax
	mov edx,Caller.Frame
	lea ecx,LoadLibrary2ndDispatch
	mov edx,STACK_FRAME.Next[edx]
	xchg STACK_FRAME.Ip[edx],ecx
	mov gChainDispatch,ecx
	mov edx,dword ptr [edx + sizeof(STACK_FRAME)]	; Arg.
	mov gLoadLibraryArg,edx
	.endif
	xor eax,eax
	ret
LdrpManifestProberRoutine endp

LdrSetDllManifestProber proto :PVOID

_imp__LoadLibraryA proto :PSTR

$Dll	CHAR "psapi.dll",0

Ep proc
Local GpSize:ULONG
Local OldProtect:ULONG
	mov gSnapshot.GpBase,NULL
	mov GpSize,1000H * X86_PAGE_SIZE
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr gSnapshot.GpBase, 0, addr GpSize, MEM_COMMIT, PAGE_READWRITE
	mov ebx,gSnapshot.GpBase
	%NTERR
	add gSnapshot.GpBase,0FFFH * X86_PAGE_SIZE
	mov GpSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr gSnapshot.GpBase, addr GpSize, PAGE_NOACCESS, addr OldProtect
	%NTERR
	mov gSnapshot.GpLimit,ebx
	mov gSnapshot.GpBase,ebx
	lea ecx,gSnapshot.GpLimit
	push eax
	push eax
	push eax
	push eax
	push eax
	push 1
	push GCBE_PARSE_SEPARATE
	push ecx
	push dword ptr [_imp__LoadLibraryA]
	%GPCALL GP_PARSE
	%NTERR
	invoke LdrSetDllManifestProber, offset LdrpManifestProberRoutine
	invoke LoadLibrary, addr $Dll
	%APIERR
	ret
Ep endp
end Ep