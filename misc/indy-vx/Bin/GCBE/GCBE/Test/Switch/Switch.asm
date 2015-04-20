	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
	
	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib
	
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
	include ..\..\Bin\Gcbe.inc
	
.data
Snapshot		GP_SNAPSHOT <>
ThreadHandle	HANDLE NtCurrentThread
CrossTable	BYTE X86_PAGE_SIZE*20 DUP (?)
BuildBuffer	BYTE X86_PAGE_SIZE*20 DUP (90H)

.code
PcStackBase	equ 4
PcStackLimit	equ 8

xSetCtxRoutine proc Ip:PVOID, Gp:PVOID, Arg:PVOID
Local Context:CONTEXT
	mov Context.ContextFlags,CONTEXT_CONTROL
	invoke ZwGetContextThread, ThreadHandle, addr Context
	mov ecx,Ip
	.if !Eax
	mov Context.regEip,ecx
	   invoke ZwSetContextThread, ThreadHandle, addr Context
	.endif
	ret
xSetCtxRoutine endp

xFrEnumRoutine proc uses ebx Mode:ULONG, Frame:PSTACK_FRAME_EX, Arg:PVOID
Local ThreadInformation:THREAD_BASIC_INFORMATION
Local Context:CONTEXT
	invoke ZwQueryInformationThread, ThreadHandle, ThreadBasicInformation, addr ThreadInformation, sizeof(THREAD_BASIC_INFORMATION), NULL
	.if !Eax
   	   mov ebx,Frame
	   assume ebx:PSTACK_FRAME_EX
	   mov Context.ContextFlags,CONTEXT_CONTROL
	   invoke ZwGetContextThread, ThreadHandle, addr Context
	   mov edx,ThreadInformation.TebBaseAddress
	   .if !Eax
	      .if [ebx].Ref
	         mov ecx,[ebx].Ref
	         mov ecx,STACK_FRAME.Next[ecx]
	      .else
	         mov ecx,Context.regEbp
	      .endif
	      cmp dword ptr[edx + PcStackBase],ecx
	      jna Error
	      cmp dword ptr[edx + PcStackLimit],ecx
	      ja Error
	      mov [ebx].Ref,ecx
	      push STACK_FRAME.Next[ecx]
	      push STACK_FRAME.Ip[ecx]
	      pop [ebx].Sfc.Ip
	      pop [ebx].Sfc.Next
	   .endif
	.endif
Exit:
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
xFrEnumRoutine endp

xFrLoadRoutine proc Frame:PSTACK_FRAME, Ip:PVOID, Gp:PVOID, Arg:PVOID
	mov ecx,Frame
	mov edx,Ip
	xor eax,eax
	mov STACK_FRAME.Ip[ecx],edx
	ret
xFrLoadRoutine endp

GP_NESTING_LEVEL		equ 5

$Msg	CHAR "..",0

_imp__MessageBoxA proto :dword, :dword, :dword, :dword

ThreadRoutine proc Arg:PVOID
	invoke MessageBox, NULL, addr $Msg, addr $Msg, MB_OK
	ret
ThreadRoutine endp

Ep proc
Local GpSize:ULONG
Local OldProtect:ULONG
Local ThreadId:HANDLE
Local Context:CONTEXT
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
	push eax
	push eax
	push eax
	push GP_NESTING_LEVEL
	push GCBE_PARSE_SEPARATE or GCBE_PARSE_OPENLIST or GCBE_PARSE_IPCOUNTING
	push ecx
	push dword ptr [_imp__MessageBoxA]
	%GPCALL GP_PARSE
	%NTERR
	lea ecx,BuildBuffer
	lea edx,CrossTable
	push ecx
	push edx
	push Snapshot.GpLimit
	push Snapshot.GpBase
	%GPCALL GP_BUILD_GRAPH
	%NTERR
	invoke CreateThread, NULL, 0, addr ThreadRoutine, 0, 0, addr ThreadId
	mov ThreadHandle,eax
	%APIERR
	invoke Sleep, 100
	invoke ZwSuspendThread, ThreadHandle, NULL
	%NTERR
	mov Context.ContextFlags,CONTEXT_CONTROL
	invoke ZwGetContextThread, ThreadHandle, addr Context
	%NTERR
	push eax
	push offset xFrLoadRoutine
	push eax
	push offset xFrEnumRoutine
	push eax
	push offset xSetCtxRoutine
	push GP_NESTING_LEVEL - 1
	push Context.regEip
	push SWT_ENABLE_ROUTING or SWT_CURRENT_CALLER
	push offset Snapshot
	%GPCALL GP_SWITCH_THREAD
	%NTERR
	invoke ZwResumeThread, ThreadHandle, NULL
	%NTERR
	invoke WaitForSingleObject, ThreadHandle, INFINITE
	ret
Ep endp
end Ep