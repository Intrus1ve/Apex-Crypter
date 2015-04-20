; \IDP\Public\User\Bin\Graph\Dasm\Relocs\Fix.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc

GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

.code
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

LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne @f
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne @f
	cmp [edx].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne @f
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne @f
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je @f
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
@@:
	ret
LdrImageNtHeader endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Перечисление фиксапов для ссылки.
;
LdrEnumerateFixups proc uses ebx esi edi ImageBase:PVOID, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local ExitFlag:BOOLEAN
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	invoke LdrImageNtHeader, ImageBase, addr ExitFlag
	test eax,eax
	mov ecx,ExitFlag
	jnz Exit
	mov esi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	mov edi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory._Size[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	test esi,esi
	mov edx,Ip
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[ecx]
	jz Error
	sub edx,ImageBase
	jbe Error
	cmp edx,ecx
	jnb Error
	test edi,edi
	jz Error
	add esi,ImageBase
	add edi,esi	; Limit
	assume esi:PIMAGE_BASE_RELOCATION
Scan:
	mov ebx,[esi].SizeOfBlock
	sub ebx,sizeof(IMAGE_BASE_RELOCATION)
	jbe Error		; ..
	shr ebx,1
@@:
	movzx eax,word ptr [esi + ebx*2 + sizeof(IMAGE_BASE_RELOCATION) - 2]
;	push eax
;	and eax,NOT(0FFFH)
;	cmp eax,IMAGE_REL_BASED_HIGHLOW
;	pop eax
;	jne Error
	and eax,0FFFH
	add eax,[esi].VirtualAddress
	mov ecx,Ip
	add eax,ImageBase
	.if dword ptr [eax] == ecx
	lea edx,ExitFlag
	mov ExitFlag,FALSE
	push edx
	push CallbackParameter
	push eax
	push ImageBase
	Call CallbackRoutine
	cmp ExitFlag,FALSE
	jne Exit
	.endif
	dec ebx
	jnz @b
Next:
	add esi,[esi].SizeOfBlock
	cmp esi,edi
	jb Scan
	xor eax,eax
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
LdrEnumerateFixups endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CALLBACK_DATA struct
Routine	PVOID ?
Parameter	PVOID ?
CALLBACK_DATA ends
PCALLBACK_DATA typedef ptr CALLBACK_DATA

_$_SearchCallback:
	GET_CURRENT_GRAPH_ENTRY
SearchCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, CallbackData:PCALLBACK_DATA, ExitFlags:PBOOLEAN
	mov eax,Fixup
	mov ecx,CallbackData
	dec eax
	cmp byte ptr [eax],68H
	jne @f
	push ExitFlags
	push CALLBACK_DATA.Parameter[ecx]
	push eax
	push ImageBase
	Call CALLBACK_DATA.Routine[ecx]
@@:
	ret
SearchCallbackInternal endp

; +
; Ищет инструкцию Push XXXX для ссылки сканируя таблицу базовых поправок.
;
LdrSearchPushReferenceInRelocationTable proc ImageBase:PVOID, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
	lea ecx,CallbackRoutine
	Call _$_SearchCallback
	invoke LdrEnumerateFixups, ImageBase, Ip, Eax, Ecx
	ret
LdrSearchPushReferenceInRelocationTable endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Ищет строку ASCII "LDR: Tls Found in %wZ at %p",LF
; [Сообщение может отличаться в версиях.]
;
LgSearchMessage proc uses edi ImageBase:PVOID, Message:PVOID
Local ImageHeader:PIMAGE_NT_HEADERS
	mov edi,ImageBase
	invoke LdrImageNtHeader, Edi, addr ImageHeader
	test eax,eax
	mov ecx,ImageHeader
	jnz Exit
	add edi,IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode[ecx]
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode[ecx]
	cld
	mov al,'L'
	mov edx,Message
@@:
	repne scasb
	jne @f
	cmp dword ptr [edi]," :RD"
	jne @b
	cmp dword ptr [edi + 4]," slT"
	jne @b
	cmp dword ptr [edi + 2*4],"nuoF"
	jne @b
	dec edi
	xor eax,eax
	mov dword ptr [edx],edi
	jmp Exit
@@:
	mov eax,STATUS_NOT_FOUND
Exit:
	ret
LgSearchMessage endp

_$_LgSearchCallback:
	GET_CURRENT_GRAPH_ENTRY
LgSearchCallback proc ImageBase:PVOID, Ip:PVOID, Message:PVOID, ExitFlag:PBOOLEAN
	mov eax,Message
	mov ecx,Ip
	mov edx,ExitFlag
	mov dword ptr [eax],ecx
	mov byte ptr [edx],1
	xor eax,eax
	ret
LgSearchCallback endp

Entry proc
Local Message:PVOID
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]
	invoke LgSearchMessage, Ebx, addr Message
	test eax,eax
	lea ecx,Message
	.if Zero?
	Call _$_LgSearchCallback
	invoke LdrSearchPushReferenceInRelocationTable, Ebx, Message, Eax, Ecx
	.if !Eax
	int 3
; В случае успеха Message будет содержать указатель в LdrpInitializeTls().
; Далее можно найти её начало(..\Belong\Ip.asm, SearchRoutineEntry()). 
	.endif
	.endif
	ret
Entry endp
end Entry