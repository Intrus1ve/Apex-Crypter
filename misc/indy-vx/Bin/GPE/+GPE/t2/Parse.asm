	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
_imp__LdrLoadDll proto :PWCHAR, :PULONG, :PUNICODE_STRING, :PHANDLE

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

.code
GCBE_PARSE_NL_UNLIMITED	equ -1

TRACE_DATA struct
ScanBase	PVOID ?
ScanLimit	PVOID ?
Message	PSTR ?
MsgLength	ULONG ?
Gp		PVOID ?
TRACE_DATA ends
PTRACE_DATA typedef ptr TRACE_DATA

TraceCallback proc uses ebx esi edi GpEntry:PVOID, TraceData:PTRACE_DATA
    mov eax,GpEntry
    test dword ptr [eax + EhEntryType],TYPE_MASK
    mov ebx,TraceData
    jne Exit    ; !HEADER_TYPE_LINE
    assume eax:PBLOCK_HEADER
    mov esi,[eax].Address
    mov edi,[eax]._Size
    assume ebx:PTRACE_DATA
Ip:
    push esi    ; Ip
    %GPCALL GP_LDE    ; LDE()
    cmp al,5
    jne @f
    cmp byte ptr [esi],68H    ; push imm32
    mov edx,dword ptr [esi + 1]    ; ref.
    jne @f
    cmp [ebx].ScanBase,edx
    ja @f
    cmp [ebx].ScanLimit,edx
    jbe @f
    push esi
    push edi
    mov esi,edx
    mov edi,[ebx].Message
    mov ecx,[ebx].MsgLength
    cld
    repe cmpsb
    pop edi
    pop esi
    jne @f
    mov eax,GpEntry
    mov [ebx].Gp,eax
    jmp Exit    
@@:
    add esi,eax
    sub edi,eax
    ja Ip
Exit:
    xor eax,eax
    ret
TraceCallback endp

$Message	CHAR "LdrpResolveDllName", 0

$Ldrp	CHAR "Def.: LdrpResolveDllName(), Address: 0x%p, Arg's: %x", 13, 10, 0

	assume fs:nothing
Ep proc
Local GpSize:ULONG
Local Snapshot:GP_SNAPSHOT
Local ArgsCount:ULONG
Local OldProtect:ULONG
Local TraceData:TRACE_DATA
Local Gp:PVOID
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
	push GCBE_PARSE_NL_UNLIMITED
	push GCBE_PARSE_DISCLOSURE
	push ecx
	push dword ptr [_imp__LdrLoadDll]
	%GPCALL GP_PARSE
	%NTERR
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov esi,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	invoke RtlImageNtHeader, Esi
	%APIERR
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode[eax]
	mov edx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode[eax]
	mov TraceData.Gp,NULL
	add ecx,esi
	lea edx,[edx + esi - sizeof $Message]
	mov TraceData.Message,offset $Message
	mov TraceData.MsgLength,sizeof $Message
	mov TraceData.ScanBase,ecx
	mov TraceData.ScanLimit,edx
	lea ecx,TraceData
	lea edx,TraceCallback
	push ecx
	push edx
	push ebx
	%GPCALL GP_TRACE
	%NTERR
	.if TraceData.Gp == NULL
	Int 3
	.endif
	lea ecx,Gp
	lea edx,Snapshot
	push ecx
	push eax
	push eax
	push 1
	push eax
	push TraceData.Gp
	push edx
	%GPCALL GP_SEARCH_ROUTINE_ENTRY
	%NTERR
	mov ebx,Gp	; ref.
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	.if Eax != HEADER_TYPE_CALL
	Int 3
	.endif
	assume ebx:PCALL_HEADER
	
	mov ecx,[ebx].BranchLink
	lea eax,ArgsCount
	and ecx,NOT(TYPE_MASK)
	push eax
	push ecx
	%GPCALL GP_QUERY_ROUTINE_ARGS_NUMBER
	%NTERR
	
	invoke DbgPrint, addr $Ldrp, [ebx].BranchAddress, ArgsCount
	ret
Ep endp
end Ep