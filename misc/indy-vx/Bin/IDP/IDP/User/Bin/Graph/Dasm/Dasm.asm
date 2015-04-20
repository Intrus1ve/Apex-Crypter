; o GCBE
; o Indy Clerk
; o Micode
;
; \IDP\Public\User\Bin\Graph\Dasm\Dasm.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	include table.inc

.code
GCBE::
	test eax,eax
	jz RwParseRoutine
	dec eax
	jz RwTraceRawTable
	dec eax
	jz MmInitializeMemoryManagment
	dec eax
	jz MmUninitializeMemoryManagment
	dec eax
	jz MmAllocateBuffer
	dec eax
	jz MmFreeBuffer
	dec eax
	jz QueryOpcodeSize
	dec eax
	jz QueryOpcodeTypeEx
	dec eax
	jz NtEncodeEntriesList
	mov eax,STATUS_UNSUCCESSFUL
	retn

	include op.asm
	include ldasm.asm
	include ..\Mm\Mm.asm
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Разбивает описатель блока на два и связывает их.
;
RwInsertLineEntryInternal proc uses ebx Entry:PBLOCK_HEADER, Address:PVOID
	mov ecx,Entry
	assume ecx:PBLOCK_HEADER
	mov ebx,Address
	mov edx,[ecx].Link.Flink
	and edx,NOT(TYPE_MASK)
	and ecx,NOT(TYPE_MASK)
	assume esi:PBLOCK_HEADER
	assume edx:PBLOCK_HEADER
	test edx,edx
	mov [ecx].Link.Flink,esi
	mov [esi].Link.Flink,edx
	.if !Zero?
	and [edx].Link.Blink,TYPE_MASK
	or [edx].Link.Blink,esi
	.endif
	mov [esi].Link.Blink,ecx
	mov [esi].Address,ebx
	mov edx,[ecx]._Size
	sub ebx,[ecx].Address
	jna @f
	mov [ecx]._Size,ebx
	sub edx,ebx
	jbe @f
	mov eax,esi
	mov [esi]._Size,edx
	mov [esi].UserData,NULL
	add esi,ENTRY_HEADER_SIZE
	ret
@@:
	xor eax,eax
	ret
RwInsertLineEntryInternal endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Ищет описатель для адреса в таблице.
; Eax - указатель на описатель.
;
RwSearchEntryForAddress proc BranchTable:PVOID, BranchTableLimit:PVOID, Address:PVOID, SearchCallback:PVOID, CallbackParameter:PVOID
	mov eax,BranchTable
	cmp BranchTableLimit,eax
	je Callback
	assume eax:PBLOCK_HEADER
	.if SearchCallback
	push TRUE
	push CallbackParameter
	push Address
	Call SearchCallback
	test eax,eax
	jnz Exit
	mov eax,BranchTable
	.endif
Entry:
	mov edx,[eax].Address
	cmp Address,edx
	je Exit
	jb Next
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	jnz Next
; Учитываем ситуацию когда ветвление не на начало инструкции(
; часть инструкции образует новую). В этом случае следует доб
; авить новую инструкцию в граф. Это редкая ситуация, не обра
; батываем её.
	add edx,[eax]._Size
	cmp Address,edx
	jb Exit
Next:
	add eax,ENTRY_HEADER_SIZE
	cmp BranchTableLimit,eax
	ja Entry
Callback:
	.if SearchCallback
	push FALSE
	push CallbackParameter
	push Address
	Call SearchCallback
	.else
Error:
	xor eax,eax
	.endif
Exit:
	ret
RwSearchEntryForAddress endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
comment '
 Для каждой инструкции вызывается пользовательская 
 процедура обратного вызова, для определения конца 
 необходимой процедуры.

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
  IN PVOID Entry,
  IN OUT PVOID *BranchTable,
  IN ULONG ParseFlags,
  IN PVOID LastIp OPTIONAL,
  IN PPARSE_CALLBACK_ROUTINE ParseCallbackRoutine OPTIONAL,
  IN PVOID ParseCallbackParameter,
  IN PSEARCH_CALLBACK_ROUTINE SearchCallbackRoutine OPTIONAL,
  IN PVOID SearchCallbackParameter
  );
  '
GCBE_PARSE_DISCLOSURE	equ 01B
GCBE_PARSE_SEPARATE		equ 10B

RwParseRoutine proc uses ebx esi edi Entry:PVOID, BranchTable:PVOID, ParseFlags:ULONG, LastIp:PVOID, ParseCallbackRoutine:PVOID, ParseCallbackParameter:PVOID, SearchCallbackRoutine:PVOID, SearchCallbackParameter:PVOID
Local LastEntry:PBRANCH_HEADER
Local BranchTableEntry:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov esi,BranchTable
	mov ebx,Entry
	mov esi,dword ptr [esi]
	mov Entry,esp	; /BranchStack
	mov edi,esi
	mov LastEntry,NULL
	mov BranchTableEntry,esi
NewBlock:
	mov dword ptr [edi + EhBlink],NULL
Block:
	.if ParseCallbackRoutine != NULL
	push ParseCallbackParameter
	push ebx
	push edi
	Call ParseCallbackRoutine
	test eax,eax
	mov edx,eax
	jnz CallbackEnd
	.endif
Block2:
	cmp LastIp,ebx
	mov dword ptr [edi + EhAddress],ebx
	jne @f
	mov edx,LastIp
CallbackEnd:
	xor ecx,ecx
	mov LastEntry,edi
	jmp JmpEntry
@@:	
	invoke QueryOpcodeType, Ebx
	test eax,eax
	jnz Branch
	assume edi:PBLOCK_HEADER
	add esi,ENTRY_HEADER_SIZE
	mov [edi].Link.Flink,HEADER_TYPE_LINE
	mov [edi].UserData,eax
	invoke IsRetOpcode, Ebx
	test eax,eax
	mov [edi]._Size,eax
	jnz PopEntry
; + Line
NextLine:
	invoke QueryOpcodeSize, Ebx
	add [edi]._Size,eax
	add ebx,eax
	invoke RwSearchEntryForAddress, BranchTableEntry, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertLine
	.if ParseCallbackRoutine != NULL
	push ParseCallbackParameter
	push ebx
	push edi
	Call ParseCallbackRoutine
	test eax,eax
	mov edx,eax
	jnz @f
	.endif
	.if LastIp == Ebx
	mov edx,LastIp
@@:
	xor ecx,ecx
	mov LastEntry,edi
	mov eax,HEADER_TYPE_JMP
	.else
	invoke QueryOpcodeType, Ebx
	test eax,eax
	jnz BranchNew
		test ParseFlags,GCBE_PARSE_SEPARATE
		.if !Zero?
		lea eax,[edi + ENTRY_HEADER_SIZE]
		or dword ptr [edi + EhFlink],eax
		mov dword ptr [eax + EhBlink],edi
		mov edi,eax
		jmp Block2
		.endif
	invoke IsRetOpcode, Ebx
	test eax,eax
	jz NextLine
	add [edi]._Size,eax
	jmp PopEntry
	.endif
BranchNew:
	push eax
	lea eax,[edi + ENTRY_HEADER_SIZE]
	or dword ptr [edi + EhFlink],eax
	mov dword ptr [eax + EhBlink],edi
	mov edi,eax
	pop eax
	mov dword ptr [edi + EhAddress],ebx
Branch:
	cmp eax,HEADER_TYPE_JXX
	jne Branch2
; + Jxx opcode.
	add esi,ENTRY_HEADER_SIZE
	assume edi:PXX_BRANCH_HEADER
; Сохраняем описатель в стеке.
	push edi
	mov [edi].BranchAddress,edx	; Edx - адрес ветвления.
	mov [edi].BranchLink,NULL	; Определим далее.
	mov [edi].Link.Flink,HEADER_TYPE_JXX
	mov [edi].UserData,NULL
	push ecx
	invoke QueryPrefixLength, Ebx
	pop edx
	movzx eax,byte ptr [ebx + eax]
	cmp al,0E0h
	jb @f
	cmp al,0E3h
	ja @f
	or dword ptr [edi + EhJccType],BRANCH_CX_FLAG
@@:
	add ebx,edx
	invoke RwSearchEntryForAddress, BranchTableEntry, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertLine
	lea eax,[edi + ENTRY_HEADER_SIZE]
	or dword ptr [edi + EhFlink],eax
	mov dword ptr [eax + EhBlink],edi
	mov edi,eax
	jmp Block
InsertLine:
	.if dword ptr [Eax + EhAddress] == Ebx
	mov dword ptr [eax + EhBlink],edi
	or [edi].Link.Flink,eax
	.else
	invoke RwInsertLineEntryInternal, Eax, Ebx
	test eax,eax
	jz ParseEnd
	.endif
	jmp PopEntry
Branch2:
	cmp Eax,HEADER_TYPE_CALL
	jne JmpEntry
; + Call opcode.
	add esi,ENTRY_HEADER_SIZE
	assume edi:PCALL_HEADER
	mov [edi].UserData,NULL
	mov [edi].BranchLink,NULL
	mov [edi].Link.Flink,HEADER_TYPE_CALL
	.if Ecx
	mov [edi].BranchAddress,edx	; Edx - адрес ветвления.
	or [edi].Link.Blink,BRANCH_DEFINED_FLAG
	invoke QueryOpcodeSize, Ebx
	add ebx,eax
	.else
	mov [edi].BranchAddress,NULL
	and [edi].Link.Blink,NOT(TYPE_MASK)
	invoke QueryOpcodeSize, Ebx
	add ebx,eax
	jmp CloseCall
	.endif
	test ParseFlags,GCBE_PARSE_DISCLOSURE
	jz CloseCall
	or dword ptr [edi + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
; Сохраняем описатель в стеке.
	push edi
; Раскрываем процедурное ветвление.
	invoke RwSearchEntryForAddress, BranchTableEntry, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertLine
CloseCall:
	lea eax,[edi + ENTRY_HEADER_SIZE]
	or dword ptr [edi + EhFlink],eax
	mov dword ptr [eax + EhBlink],edi
	mov edi,eax
	jmp Block
JmpEntry:
; + Jmp opcode.
	add esi,ENTRY_HEADER_SIZE
	assume edi:PBRANCH_HEADER
	test ecx,ecx
	mov [edi].Link.Flink,HEADER_TYPE_JMP
	mov [edi].UserData,NULL
	jnz @f
	mov [edi].BranchLink,NULL
	mov [edi].BranchAddress,NULL
	and [edi].Link.Blink,NOT(TYPE_MASK)
	jmp PopEntry
@@:
	mov ebx,edx
	or [edi].Link.Blink,BRANCH_DEFINED_FLAG
	mov [edi].BranchAddress,ebx	; Edx - адрес ветвления.
	invoke RwSearchEntryForAddress, BranchTableEntry, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jz @f
InsertBranchLine:
	.if dword ptr [Eax + EhAddress] != Ebx
	invoke RwInsertLineEntryInternal, Eax, Ebx
	test eax,eax
	jz ParseEnd
	.endif
	or [edi].BranchLink,eax
	jmp PopEntry
@@:
	lea eax,[edi + ENTRY_HEADER_SIZE]
	mov dword ptr [eax + EhBlink],NULL
	mov [edi].BranchLink,eax
	mov edi,eax
	jmp Block
;  Jxx -> branch link.
PopEntry:
	cmp Entry,esp	; /BranchStack
	mov eax,esi
	jz ParseEnd
	pop edi
	assume edi:PBRANCH_HEADER
	mov ebx,[edi].BranchAddress
	invoke RwSearchEntryForAddress, BranchTableEntry, Esi, Ebx, SearchCallbackRoutine, SearchCallbackParameter
	test eax,eax
	jnz InsertBranchLine
	or [edi].BranchLink,esi
	mov edi,esi
	jmp NewBlock
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Return:
	Call SEH_Epilog
	mov edx,LastEntry
	ret
ParseEnd:
	mov ecx,BranchTable
	mov dword ptr [ecx],eax
	xor eax,eax
	jmp Return
RwParseRoutine endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
comment '
 Перечисление входов таблицы ветвлений.
 Выполняется инверсия флага ACCESSED_MASK_FLAG в каждом входе.
 Рекурсивные вызовы не допускаются!

typedef VOID (*PTRACE_CALLBACK_ROUTINE)(
    IN PVOID TableEntry,
    IN PVOID CallbackParameter
    );

typedef NTSTATUS (*PENTRY)(
  IN PVOID RawTable,
  IN PTRACE_CALLBACK_ROUTINE CallbackRoutine,
  IN PVOID CallbackParameter
  )'

CALL_STACK_MARKER	equ 00B
JXX_STACK_MARKER	equ 01B
;JMP_STACK_MARKER	equ 10B

RwTraceRawTable proc uses ebx esi RawTable:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local EntryStack:PVOID
Local AccessFlag:DWORD
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,RawTable
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
BranchEntry:
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz PopEntry
	mov ebx,[ebx].BranchLink
	and ebx,NOT(TYPE_MASK)
	jmp FindHead
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Return:
	Call SEH_Epilog
	ret
StackEnd:
	xor eax,eax
	jmp Return
RwTraceRawTable endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
end RwTraceRawTable