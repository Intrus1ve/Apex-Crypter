comment '
 Перечисление входов таблицы ветвлений.
 Выполняется инверсия флага ACCESSED_MASK_FLAG в каждом входе.
 Рекурсивные вызовы не допускаются!

typedef NTSTATUS (*PTRACE_CALLBACK_ROUTINE)(
    IN PVOID GpEntry,
    IN PVOID CallbackParameter
    );

typedef NTSTATUS (*PENTRY)(
  IN PVOID Graph,
  IN PTRACE_CALLBACK_ROUTINE CallbackRoutine,
  IN PVOID CallbackParameter
  )'

CALL_STACK_MARKER	equ 00B
JXX_STACK_MARKER	equ 01B
JMP_STACK_MARKER	equ 10B

GpTrace proc uses ebx esi edi Graph:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local EntryStack:PVOID
Local AccessFlag:DWORD
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,Graph
	cld
	mov eax,dword ptr [ebx + EhAccessFlag]
	mov EntryStack,esp
	and eax,ACCESSED_MASK_FLAG
	mov AccessFlag,eax
FindHead:
	mov edx,dword ptr [ebx + EhBlink]
	and edx,NOT(TYPE_MASK)
	jz NewBlock
	mov ebx,edx
	jmp FindHead
NewBlock:
	mov edx,dword ptr [ebx + EhAccessFlag]
	and edx,ACCESSED_MASK_FLAG
	cmp AccessFlag,edx
	jne PopEntry
	xor dword ptr [ebx + EhAccessFlag],ACCESSED_MASK_FLAG
	push CallbackParameter
	push ebx
	Call CallbackRoutine
	test eax,eax
	jnz Return
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	jz LineEntry
	cmp eax,HEADER_TYPE_CALL
	jne @f
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz LineEntry
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz LineEntry
	push ebx
	jmp LineEntry
@@:
	assume ebx:PBRANCH_HEADER
	cmp eax,HEADER_TYPE_JXX
	je @f
; Jmp
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz PopEntry
	jmp NewEntry
@@:
; Jxx.
	mov eax,[ebx].BranchLink
	and eax,NOT(TYPE_MASK)
	or eax,JXX_STACK_MARKER
	push eax
LineEntry:
	mov ebx,[ebx].Link.Flink
	and ebx,NOT(TYPE_MASK)
	jnz NewBlock
PopEntry:
	mov ecx,EntryStack
	sub ecx,esp
	je StackEnd
	shr ecx,2
	mov edx,ecx
@@:
	test dword ptr [esp + 4*ecx - 4],JXX_STACK_MARKER
	jnz PopJxxEntry
	loop @b
PopCallEntry:
	lea edi,[esp + 4*edx - 4]
	lea esi,[edi - 4]
	mov ebx,dword ptr [esp + 4*edx - 4]
	mov ecx,edx
	std
	btr ebx,0	; and ebx,NOT(JXX_STACK_MARKER)
	rep movsd
	add esp,4
	assume ebx:PCALL_HEADER
NewEntry:
	mov ebx,[ebx].BranchLink
	cld
	and ebx,NOT(TYPE_MASK)
	mov eax,dword ptr [ebx + EhAccessFlag]
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
	jmp FindHead
PopJxxEntry:
	lea edi,[esp + 4*ecx - 4]
	lea esi,[edi - 4]
	mov ebx,dword ptr [esp + 4*ecx - 4]
	std
	btr ebx,0	; and ebx,NOT(JXX_STACK_MARKER)
	rep movsd
	add esp,4
	mov eax,dword ptr [ebx + EhAccessFlag]
	cld
	and eax,ACCESSED_MASK_FLAG
	cmp AccessFlag,eax
	jne PopEntry
	jmp FindHead
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Return:
	Call SEH_Epilog
	ret
StackEnd:
	xor eax,eax
	jmp Return
GpTrace endp