; Надстройка для парсера.
;
; \IDP\Public\User\Bin\Graph\Dasm\Belong\Ip.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc

BREAKERR macro
	.if Eax
	int 3
	.endif
endm

BREAK macro
	int 3
endm

.code
	include ..\Dasm.inc

GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

_$_GetCallbackReference::
	pop eax
	ret

SEH_Prolog proc C
	pop ecx
	push ebp
	push eax
	Call SEH_GetRef
	push eax
	assume fs:nothing
	push dword ptr fs:[TEB.Tib.ExceptionList]
	mov dword ptr fs:[TEB.Tib.ExceptionList],esp
	jmp ecx
SEH_Prolog endp

SEH_Epilog proc C
	pop ecx
	pop dword ptr fs:[TEB.Tib.ExceptionList]
	lea esp,[esp + 3*4]
	jmp ecx
SEH_Epilog endp

SEH_GetRef proc C
	GET_CURRENT_GRAPH_ENTRY
	mov eax,dword ptr [esp + 4]
	mov esp,dword ptr [esp + 2*4]	; (esp) -> ExceptionList
	mov eax,EXCEPTION_RECORD.ExceptionCode[eax]
	mov ebp,dword ptr [esp + 3*4]
	jmp dword ptr [esp + 2*4]
SEH_GetRef endp

SNAPSHOT_INFORMATION struct
Routine		PVOID ?
BufferHandle	HANDLE ?
BufferBase	PVOID ?
BufferLimit	PVOID ?
ParseFlags	DWORD ?
SNAPSHOT_INFORMATION ends
PSNAPSHOT_INFORMATION typedef ptr SNAPSHOT_INFORMATION
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Создаёт слепок процедуры.
;
comment '
typedef PVOID (*PPARSE_CALLBACK_ROUTINE)(
   IN PVOID GraphEntry,
   IN PVOID Instruction,
   IN PVOID CallbackParameter
   );

typedef PVOID (*PSEARCH_CALLBACK_ROUTINE)(
   IN PVOID Address,
   IN PVOID CallbackParameter
   IN BOOLEAN FirstSearch
   );

typedef NTSTATUS (*PENTRY)(
   IN PVOID Ip,
   OUT PSNAPSHOT_INFORMATION SnapshotInformation,
   IN ULONG ParseFlags,
   IN PVOID LastIp OPTIONAL,
   IN PPARSE_CALLBACK_ROUTINE ParseCallbackRoutine OPTIONAL,
   IN PVOID ParseCallbackParameter,
   IN PSEARCH_CALLBACK_ROUTINE SearchCallbackRoutine OPTIONAL,
   IN PVOID SearchCallbackParameter
   );
   '
CreateSnapshot proc Routine:PVOID, SnapshotInformation:PSNAPSHOT_INFORMATION, Flags:DWORD, LastIp:PVOID, ParseCallbackRoutine:PVOID, ParseCallbackParameter:PVOID, SearchCallbackRoutine:PVOID, SearchCallbackParameter:PVOID
Local Snapshot:SNAPSHOT_INFORMATION
	mov eax,MM_INITIALIZE
	Call GCBE
	test eax,eax
	lea ecx,Snapshot.BufferHandle
	lea edx,Snapshot.BufferBase
	jnz Exit
	push ecx
	push edx
	push eax
	push PAGE_SIZE*1000H	; 16M
	mov eax,MM_ALLOCATE_BUFFER
	Call GCBE
	test eax,eax
	mov ecx,Snapshot.BufferBase
	jnz Exit
	push SearchCallbackParameter
	lea edx,Snapshot.BufferLimit
	push SearchCallbackRoutine
	mov Snapshot.BufferLimit,ecx
	push ParseCallbackParameter
	push ParseCallbackRoutine
	push LastIp
	push Flags
	push edx
	push Routine
	mov eax,GP_PARSE
	Call GCBE
	test eax,eax
	mov ecx,SnapshotInformation
	jnz Error
	push Flags
	mov edx,Routine
	push Snapshot.BufferHandle
	push Snapshot.BufferBase
	push Snapshot.BufferLimit
	assume ecx:PSNAPSHOT_INFORMATION
	mov [ecx].Routine,edx
	pop [ecx].BufferLimit
	pop [ecx].BufferBase
	pop [ecx].BufferHandle
	pop [ecx].ParseFlags
Exit:
	ret
Error:
	push eax
	push Snapshot.BufferHandle
	mov eax,MM_FREE_BUFFER
	Call GCBE
	pop eax
	jmp Exit
CreateSnapshot endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Освобождает память слепка.
;
FreeSnapshot proc uses ebx SnapshotInformation:PSNAPSHOT_INFORMATION
	mov ebx,SnapshotInformation
	assume ebx:PSNAPSHOT_INFORMATION
	push [ebx].BufferHandle
	mov eax,MM_FREE_BUFFER
	Call GCBE
	.if !Eax
	mov [ebx].BufferHandle,eax
	mov [ebx].BufferBase,eax
	mov [ebx].BufferLimit,eax
	mov [ebx].ParseFlags,eax
	.endif
	ret
FreeSnapshot endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Определяет принадлежность инструкции исходной процедуре.
;
FastCheckIpBelongToSnapshot proc uses ebx edi SnapshotInformation:PSNAPSHOT_INFORMATION, Ip:PVOID, GraphEntry:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,SnapshotInformation
	assume ebx:PSNAPSHOT_INFORMATION
	mov edi,GraphEntry
	mov eax,[ebx].BufferBase
	cld
	cmp [ebx].BufferLimit,eax
	jbe Error
	assume eax:PBLOCK_HEADER
Entry:
	mov edx,[eax].Address
	cmp Ip,edx
	je Load
	jb Next
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	jnz Next
	add edx,[eax]._Size
	cmp Ip,edx
	jb Load
Next:
	add eax,ENTRY_HEADER_SIZE
	cmp [ebx].BufferLimit,eax
	ja Entry
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Epilog
Load:
	stosd
; ****** Link for test *******
_$_TestIp::                 ;*
; ****************************
	xor eax,eax
	jmp Epilog
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Epilog:
	Call SEH_Epilog
	ret
FastCheckIpBelongToSnapshot endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;
TRACE_CALLBACK_DATA struct
Ip			PVOID ?
GraphEntry	PVOID ?
TRACE_CALLBACK_DATA ends
PTRACE_CALLBACK_DATA typedef ptr TRACE_CALLBACK_DATA

_$_TraceCallback:
	GET_CURRENT_GRAPH_ENTRY
CheckIpBelongToSnapshotTraceCallback proc uses ebx GraphEntry:PVOID, CallbackData:PTRACE_CALLBACK_DATA
	mov ebx,CallbackData
	assume ebx:PTRACE_CALLBACK_DATA
	mov edx,GraphEntry
	assume edx:PBLOCK_HEADER
	mov eax,[edx].Address
	cmp [ebx].Ip,eax
	je Load
	jb Exit
	mov ecx,dword ptr [edx + EhEntryType]
	and ecx,TYPE_MASK
	jnz Exit
	add eax,[edx]._Size
	cmp [ebx].Ip,eax
	jae Exit
Load:
	mov [ebx].GraphEntry,edx
Exit:
	ret
CheckIpBelongToSnapshotTraceCallback endp

; +
; Определяет принадлежность инструкции исходной процедуре.
;
CheckIpBelongToSnapshot proc uses ebx SnapshotInformation:PSNAPSHOT_INFORMATION, Ip:PVOID, GraphEntry:PVOID
Local CallbackData:TRACE_CALLBACK_DATA
	mov eax,Ip
	lea ecx,CallbackData
	mov CallbackData.GraphEntry,NULL
	mov CallbackData.Ip,eax
	push ecx
	mov edx,SnapshotInformation
	Call _$_TraceCallback
	push eax
	push SNAPSHOT_INFORMATION.BufferBase[edx]
	mov eax,GP_TRACE
	Call GCBE
	mov ecx,GraphEntry
	test eax,eax
	mov edx,CallbackData.GraphEntry
	.if Zero?
	mov dword ptr [ecx],edx
	.endif
	ret
CheckIpBelongToSnapshot endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Поиск прямой ссылки на описатель.
;
DirectSearchEntryReferenceInternal proc uses ebx GraphBase:PVOID, GraphLimit:PVOID, Entry:PVOID
	mov ebx,GraphBase
Check:
	cmp GraphLimit,ebx
	ja @f
	xor eax,eax
	jmp Exit
@@:
	cmp Entry,ebx
	mov eax,dword ptr [ebx + EhEntryType]
	je Next
	mov ecx,dword ptr [ebx + EhFlink]
	and ecx,NOT(TYPE_MASK)
	cmp Entry,ecx
	je Save
	and eax,TYPE_MASK
	jz Next
	cmp eax,HEADER_TYPE_JXX
	mov ecx,dword ptr [ebx + EhBranchLink]
	je IsValid
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz Next
IsValid:
	and ecx,NOT(TYPE_MASK)
	cmp Entry,ecx
	je Save
Next:
	add ebx,ENTRY_HEADER_SIZE
	jmp Check
Save:
	mov eax,ebx
Exit:
	ret
DirectSearchEntryReferenceInternal endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Ищет начало процедуры.
;
comment '
typedef PVOID (*PSEARCH_HEAD_CALLBACK)(
   IN PSNAPSHOT_INFORMATION SnapshotInformation,
   IN PVOID GraphEntryForSearch,
   IN PVOID GraphEntryForCheck
   );
   
typedef NTSTATUS (*PENTRY)(
   IN PSNAPSHOT_INFORMATION SnapshotInformation,
   IN PVOID Ip,
   IN ULONG NestingLevel,
   IN PSEARCH_HEAD_CALLBACK SearchCallback,
   IN PVOID SearchCallbackParameter,
   OUT PCALL_HEADER GraphEntry
   );
   '
SearchRoutineEntry proc uses ebx esi edi SnapshotInformation:PSNAPSHOT_INFORMATION, Ip:PVOID, NestingLevel:ULONG, SearchCallback:PVOID, SearchCallbackParameter:PVOID, GraphEntry:PVOID
Local Reference:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	cmp NestingLevel,0
	mov ebx,SnapshotInformation
	assume ebx:PSNAPSHOT_INFORMATION
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	jmp Exit
	.endif
	invoke FastCheckIpBelongToSnapshot, Ebx, Ip, addr Reference
	test eax,eax
	mov esi,Reference
	jnz Exit
	cld
	cmp [ebx].BufferLimit,esi
	jbe Error
	assume esi:PBLOCK_HEADER
FindHead:
	mov edx,dword ptr [esi + EhBlink]
	and edx,NOT(TYPE_MASK)
	jnz @f
	mov edi,[ebx].BufferBase
	jmp NewBlock
@@:
	mov esi,edx
	jmp FindHead
NewBlock:
	invoke DirectSearchEntryReferenceInternal, Edi, [ebx].BufferLimit, Esi
	mov Reference,eax
	.if SearchCallback != NULL
	push eax
	push esi
	push SnapshotInformation
	Call SearchCallback
	test eax,eax
	mov ecx,Reference
	jnz @f
	test ecx,ecx
	jz Error
	lea edi,[ecx + ENTRY_HEADER_SIZE]
	cmp [ebx].BufferLimit,edi
	jbe Error
	jmp NewBlock
	.endif
	test eax,eax
	jnz @f
	mov ecx,GraphEntry
	mov eax,STATUS_NO_MORE_ENTRIES
	mov dword ptr [ecx],esi
	jmp Exit
@@:
	mov esi,eax
	mov ecx,dword ptr [esi + EhEntryType]
	and ecx,TYPE_MASK
	jz FindHead	; line
	dec ecx
	jnz FindHead	; jcc/jxx
; call
	dec NestingLevel
	mov ecx,GraphEntry
	jnz FindHead
	mov dword ptr [ecx],esi
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
SearchRoutineEntry endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.data
gSnapshot	SNAPSHOT_INFORMATION <>

.code
Entry proc
Local GraphEntry:PVOID
	invoke CreateSnapshot, offset Entry, addr gSnapshot, GP_PARSE_DISCLOSURE, 0, NULL, 0, NULL, 0
	BREAKERR
	invoke SearchRoutineEntry, addr gSnapshot, offset _$_TestIp, 2, NULL, 0, addr GraphEntry
	BREAKERR
	mov eax,GraphEntry
	BREAK
	invoke FreeSnapshot, addr gSnapshot
	BREAKERR
	ret
Entry endp
end Entry