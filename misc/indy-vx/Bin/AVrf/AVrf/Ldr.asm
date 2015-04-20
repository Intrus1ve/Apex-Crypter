; o Загрузка верификатора из памяти и инициализация провайдера.
; o Indy, 2010.
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	
LDR_LOAD_DLL		equ 0
LDR_QUERY_ENTRY	equ 1
LDR_QUERY_ENTRIES	equ 2

; #define LDR_LOAD_DLL 0x00000000
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID MapAddress,
; 	IN PSTR DllName,
; 	IN PULONG DllCharacteristics OPTIONAL,
; 	OUT PVOID *ImageBase
; 	);
; 
; * Имя модуля при загрузке не имеет значения.
; 	
; #define LDR_QUERY_ENTRY 0x00000001
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID ImageBase OPTIONAL,
; 	IN PVOID HashOrFunctionName,
; 	IN PCOMPUTE_HASH_ROUTINE HashRoutine OPTIONAL,
; 	IN ULONG PartialCrc,
; 	OUT *PVOID Entry
; 	);
; 	
; typedef ULONG (*PCOMPUTE_HASH_ROUTINE)(
; 	IN ULONG UserParameter,
; 	IN PVOID Buffer,
; 	IN ULONG Length
; 	);
; 	
; * Если калбэк вычисляющий хэш(HashRoutine) не задан, то второй параметр рассматривается как указатель на имя экспорта.
; * Если база модуля не задана, то используется ntdll.
; * Калбэк должен возвратить в регистре Eax хэш для строки.
; 
; #define LDR_QUERY_ENTRIES 0x00000002
; 
; typedef NTSTATUS (*PENTRY)(
; 	IN PVOID ImageBase OPTIONAL,
; 	IN ULONG PartialCrc,
; 	IN OUT *PVOID EntriesList
; 	);
; 
; * Маркером конца списка хэшей(CRC32) является ноль.


.code
	include Ldr.inc
	include VirXasm32b.asm
	
GET_CURRENT_GRAPH_ENTRY macro
	Call _$_GetCallbackReference
endm

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

; o Не восстанавливаются Ebx, Esi и Edi.
;
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

_$_GetCallbackReference::
	pop eax
	ret
	
; +
; Поправка базы для GetModuleHandle(0).
;
LDR_FIXUP_PEB macro DllHandle
	assume fs:nothing
	mov ecx,fs:[TEB.Peb]
	mov eax,DllHandle
	lock xchg PEB.ImageBaseAddress[ecx],eax
endm

; +
; Поправка базы для загрузчика(GetModuleHandle() etc).
;
LDR_FIXUP_DATABASE macro DllHandle
	assume fs:nothing
	mov ecx,fs:[TEB.Peb]
	mov eax,DllHandle
	mov ecx,PEB.Ldr[ecx]
	mov ecx,PEB_LDR_DATA.InLoadOrderModuleList.Flink[ecx]
	lock xchg LDR_DATA_TABLE_ENTRY.DllBase[ecx],eax
endm

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

; +
; Получает базу модуля по имени.
;
xLdrGetDllHandle proc DllName:PSTR, DllHandle:PVOID
Local Entries[4]:PVOID
Local DllNameU:UNICODE_STRING
	xor ecx,ecx
	lea edx,Entries
	mov Entries[0],0F45CAC9DH	; CRC32("RtlCreateUnicodeStringFromAsciiz")
	mov Entries[4],043681CE6H	; CRC32("RtlFreeUnicodeString")
	mov Entries[2*4],0E21C1C46H	; CRC32("LdrGetDllHandle")
	mov eax,LDR_QUERY_ENTRIES
	mov Entries[3*4],ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,DllNameU
	jnz Exit
	push DllName
	push ecx
	Call Entries[0]	; RtlCreateUnicodeStringFromAsciiz()
	test eax,eax
	lea ecx,DllNameU
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	.else
	push DllHandle
	push ecx
	push NULL
	push NULL
	Call Entries[2*4]	; LdrGetDllHandle()
	lea ecx,DllNameU
	push eax
	push ecx
	Call Entries[4]	; RtlFreeUnicodeString()
	pop eax
	.endif
Exit:
	ret
xLdrGetDllHandle endp

; +
; Перечисление фиксапов для ссылки.
;
; typedef VOID (*LDR_FIXUP_ENUMERATION_CALLBACK)(
;	IN PVOID ImageBase,
;	IN PVOID Fixup,
;	IN PVOID Context,
;	IN OUT BOOLEAN *StopEnumeration
;	);
;
xLdrEnumerateFixups proc uses ebx esi edi ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
Local ExitFlag:BOOLEAN
Local SectionBaseVA:ULONG, SectionLimitVA:ULONG
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	.if ImageBase == NULL
	mov eax,fs:[TEB.Peb]
	mov ecx,PEB.LoaderLock[eax]
	mov eax,PEB.Ldr[eax]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov eax,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	mov ImageBase,eax
	.endif
	invoke LdrImageNtHeader, ImageBase, addr ExitFlag
	test eax,eax
	mov ecx,ExitFlag
	mov edx,Section
	jnz Exit
	test edx,edx
	mov esi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory.VirtualAddress[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	mov edi,IMAGE_NT_HEADERS.OptionalHeader.DataDirectory._Size[ecx + IMAGE_DIRECTORY_ENTRY_BASERELOC*sizeof(IMAGE_DATA_DIRECTORY)]
	.if !Zero?
	mov eax,IMAGE_SECTION_HEADER.VirtualAddress[edx]
	mov SectionBaseVA,eax
	add eax,IMAGE_SECTION_HEADER.VirtualSize[edx]
	mov SectionLimitVA,eax
	.endif
	test esi,esi
	mov edx,Ip
	jz Error
	test edx,edx
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[ecx]
	jz @f
	sub edx,ImageBase
	jbe Error
	cmp edx,ecx
	jnb Error
@@:
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
	cmp Section,NULL
	mov eax,[esi].VirtualAddress
	jz @f
	cmp SectionBaseVA,eax
	mov edx,SectionLimitVA
	ja Block
	cmp SectionLimitVA,eax
	jbe Block
@@:
	movzx eax,word ptr [esi + ebx*2 + sizeof(IMAGE_BASE_RELOCATION) - 2]
	mov edx,eax
	and edx,NOT(0FFFH)
	and eax,0FFFH
	cmp edx,(IMAGE_REL_BASED_HIGHLOW shl 12)
	jne Next
	add eax,[esi].VirtualAddress
	mov ecx,Ip
	add eax,ImageBase
	.if !Ecx || dword ptr [Eax] == Ecx
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
Next:
	dec ebx
	jnz @b
Block:
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
xLdrEnumerateFixups endp

; +
;
OP_PUSH32	equ 68H

LDR_CALLBACK_DATA struct
Routine	PVOID ?
Context	PVOID ?
LDR_CALLBACK_DATA ends
PLDR_CALLBACK_DATA typedef ptr LDR_CALLBACK_DATA

$LdrSearchFixup:
	GET_CURRENT_GRAPH_ENTRY
LdrSearchFixupCallbackInternal proc ImageBase:PVOID, Fixup:PVOID, CallbackData:PLDR_CALLBACK_DATA, Stop:PBOOLEAN
	mov eax,Fixup
	mov ecx,CallbackData
	dec eax
	.if byte ptr [Eax] == OP_PUSH32
	push Stop
	push LDR_CALLBACK_DATA.Context[ecx]
	push eax
	push ImageBase
	Call LDR_CALLBACK_DATA.Routine[ecx]
	.endif
	xor eax,eax
	ret
LdrSearchFixupCallbackInternal endp

; +
; Ищет инструкцию Push XXXX для ссылки сканируя таблицу базовых поправок.
;
xLdrSearchReferenceInRelocationTable proc ImageBase:PVOID, Section:PIMAGE_SECTION_HEADER, Ip:PVOID, CallbackRoutine:PVOID, CallbackParameter:PVOID
	cmp Ip,NULL
	lea ecx,CallbackRoutine
	.if Zero?
	mov eax,STATUS_INVALID_PARAMETER
	.else
	Call $LdrSearchFixup
	invoke xLdrEnumerateFixups, ImageBase, Section, Ip, Eax, Ecx
	.endif
	ret
xLdrSearchReferenceInRelocationTable endp

AVRF_ENVIRONMENT struct
pAVrfInitializeVerifier		PVOID ?
NumberOfArguments			ULONG ?
;AVrfpEnabled				PVOID ?
;AVrfpParseVerifierDllsString	PVOID ?
;pAVrfpSnapAlreadyLoadedDlls	PVOID ?
;pAVrfpVerifierProvidersList	PVOID ?
;pAVrfpVerifierLock			PVOID ?
comment '
	mov ebx,offset AVrfpVerifierProvidersList	; LIST_ENTRY
	push offset AVrfpVerifierLock
	mov dword ptr [AVrfpVerifierProvidersList + 4],ebx
	mov dword ptr [AVrfpVerifierProvidersList],ebx
	call RtlInitializeCriticalSection
	'
pAVrfpVerifierFlags			PVOID ?	; "VerifierFlags"
pAVrfpDebug				PVOID ?	; "VerifierDebug"
pAVrfpVerifierDllsString		PVOID ?	; "VerifierDlls"
AVRF_ENVIRONMENT ends
PAVRF_ENVIRONMENT typedef ptr AVRF_ENVIRONMENT

AVRF_CALLBACK_DATA struct
pDbgPrint					PVOID ?
pRtlComputeCrc32			PVOID ?
pRtlInitializeCriticalSection	PVOID ?
pAVrfBody					PVOID ?
Env						AVRF_ENVIRONMENT <>
AVRF_CALLBACK_DATA ends
PAVRF_CALLBACK_DATA typedef ptr AVRF_CALLBACK_DATA

OP_CALL_NEAR	equ 0E8H

; +
;
$AVrfSearchFixup:
	GET_CURRENT_GRAPH_ENTRY
AVrfSearchFixupCallbackInternal proc uses ebx esi edi ImageBase:PVOID, Fixup:PVOID, CallbackData:PAVRF_CALLBACK_DATA, Stop:PBOOLEAN
	mov esi,Fixup
	mov ebx,CallbackData
	dec esi
	assume ebx:PAVRF_CALLBACK_DATA
	mov edx,[ebx].pDbgPrint
	cmp byte ptr [esi],OP_PUSH32
	jne Next
	sub edx,esi
	cmp byte ptr [esi + 5],OP_CALL_NEAR
	lea edx,[edx - 10]
	jne Next
	cmp dword ptr [esi + 6],edx
	jne Next
; Диапазон не проверяем.
	mov edi,dword ptr [esi + 1]
	xor eax,eax
	cmp dword ptr [edi],'FRVA'
	mov edx,edi
	jne Next
	cld
	mov ecx,MAX_PATH
	repne scasb
	jne Next
	cmp ecx,(MAX_PATH - 40)
	jne Next
	push 39
	push edx
	push eax
	Call [ebx].pRtlComputeCrc32
	cmp eax,0F5623CCCH	; CRC32("AVRF: -*- final list of providers -*- ",LF)
	mov ecx,Stop
	jne Next
	mov [ebx].pAVrfBody,esi
	mov dword ptr [ecx],TRUE
Next:
	xor eax,eax
	ret
AVrfSearchFixupCallbackInternal endp

; +
; Поиск и парсинг AVrfInitializeVerifier().
;
xAVrfQueryEnvironment proc uses ebx esi edi AVrfEnvironment:PAVRF_ENVIRONMENT
Local AVrf:AVRF_CALLBACK_DATA
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov AVrf.pDbgPrint,0D318D52FH		; CRC32("DbgPrint")
	mov AVrf.pRtlComputeCrc32,0CACBBC36H	; CRC32("RtlComputeCrc32")
	mov AVrf.pRtlInitializeCriticalSection,08D76F9A4H	; CRC32("RtlInitializeCriticalSection")
	xor ecx,ecx
	lea edx,AVrf.pDbgPrint
	mov eax,LDR_QUERY_ENTRIES
	mov AVrf.pAVrfBody,ecx
	push edx
	push ecx
	push ecx
	Call LDR
	test eax,eax
	lea ecx,AVrf
	jnz Exit
	Call $AVrfSearchFixup
	invoke xLdrEnumerateFixups, NULL, NULL, NULL, Eax, Ecx
	test eax,eax
	mov esi,AVrf.pAVrfBody
	jnz Exit
	test esi,esi
	lea edi,[esi + 200H]
	jz Error
Ip:
	Call VirXasm32
	cmp al,3
	jne Next
	cmp byte ptr [esi],0C2H
	jne Next
	movzx eax,word ptr [esi + 1]
	mov ecx,AVrf.pDbgPrint
	mov ebx,esi
	mov AVrf.Env.NumberOfArguments,eax
	mov esi,AVrf.pAVrfBody
	mov AVrf.pDbgPrint,ecx
	lea edi,[esi - 140H]
Validate:
	cmp dword ptr [esi - 4],90909090H	; 4 x Nop
	jne Step
	cmp dword ptr [esi],8B55FF8BH
	jne Step
	mov AVrf.Env.pAVrfInitializeVerifier,esi
Ip2:
	Call VirXasm32
	cmp al,5
	jne Next2
	cmp byte ptr [esi],OP_CALL_NEAR
	jne Next2
	mov ecx,dword ptr [esi + 1]
	lea ecx,[esi + ecx + 5]
	cmp AVrf.pRtlInitializeCriticalSection,ecx
	jne Next2
	mov edi,5
;	add esi,eax
;
; AVrfpVerifierFlags передаётся в DbgPrint()/DbgPrintEx() последним параметром:
; "AVRF: %ws: pid 0x%X: flags 0x%X: application verifier enabled",LF
;
Ip3:
	Call VirXasm32
	cmp al,6
	jne Next3
	cmp word ptr [esi],35FFH		; push dword ptr [AVrfpVerifierFlags]
	jne Next3
	mov ecx,dword ptr [esi + 2]
;	add esi,eax
	mov edi,10
	mov AVrf.Env.pAVrfpVerifierFlags,ecx
Ip4:
	Call VirXasm32
	cmp al,5
	jne Next4
	cmp byte ptr [esi],OP_CALL_NEAR	; call DbgPrint/DbgPrintEx
	jne Next4
	cmp word ptr [esi + 5],0C483H		; add esp,#
	jne Next4
	cmp byte ptr [esi + 8],OP_PUSH32	; push offset AVrfpVerifierDllsString
	jne Next4
	cmp byte ptr [esi + 13],OP_CALL_NEAR	; call AVrfpParseVerifierDllsString
	jne Next4
	mov edi,dword ptr [esi + 9]
Ip5:
	Call VirXasm32
	cmp al,7
	jne Next5
@@:
	cmp word ptr [esi],05C6H	; mov byte ptr [AVrfpEnabled],1
	jne Next5
	cmp word ptr [esi + 6],0E801H
	jne Next5
	cmp word ptr [esi + 12],05F6H	; test byte ptr [AVrfpDebug],8
	jne Next5
	mov ecx,dword ptr [esi + 14]
	mov AVrf.Env.pAVrfpVerifierDllsString,edi
	mov AVrf.Env.pAVrfpDebug,ecx
	cld
	mov edi,AVrfEnvironment
	lea esi,AVrf.Env
	mov ecx,sizeof(AVRF_ENVIRONMENT)/4
	xor eax,eax
	rep movsd
	jmp Exit
SEH_Epilog_Reference:
	GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Step:
	dec esi
	cmp esi,edi
	ja Validate
	jmp Error
Next5:
	add esi,eax
	cmp esi,ebx
	jb Ip5
	jmp Error
Next4:
	add esi,eax
	dec edi
	jnz Ip4
	jmp Error
Next3:
	add esi,eax
	dec edi
	jnz Ip3
	jmp Error
Next2:
	add esi,eax
	cmp esi,ebx
	jb Ip2
	jmp Error
Next:
	add esi,eax
	cmp esi,edi
	jb Ip
Error:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
xAVrfQueryEnvironment endp

; Загрузка провайдера и инициализация среды.
; o Замена системного провайдера(verifier.dll).
; o Пользовательские провайдеры не загружаются(AVrfpVerifierDllsString -> Null).
;
xAVrfInitializeVerifier proc MapAddress:PVOID, DllCharacteristics:PULONG, VerifierFlags:ULONG, VerifierDebug:ULONG, DllHandle:PHANDLE
Local AVrf:AVRF_ENVIRONMENT
Local $DllName[4*4]:CHAR
Local xDllHandle:HANDLE
	invoke xAVrfQueryEnvironment, addr AVrf
	test eax,eax
	jnz Exit
	cmp AVrf.NumberOfArguments,3*4	; * XP, в иных версиях прототип AVrfInitializeVerifier() иной.
	je @f
	mov eax,STATUS_NOT_IMPLEMENTED
	jmp Exit
@@:
	mov dword ptr $DllName[0],'irev'
	mov dword ptr $DllName[4],'reif'
	mov dword ptr $DllName[2*4],'lld.'
	mov dword ptr $DllName[3*4],eax
	invoke xLdrGetDllHandle, addr $DllName, addr xDllHandle
	test eax,eax
	jnz @f
	mov eax,STATUS_IMAGE_ALREADY_LOADED
	jmp Exit
@@:
	cmp eax,STATUS_DLL_NOT_FOUND
	lea ecx,$DllName
	jne Exit
	push DllHandle
	push DllCharacteristics
	push ecx
	push MapAddress
	mov eax,LDR_LOAD_DLL
	Call LDR
	test eax,eax
	mov ecx,AVrf.pAVrfpVerifierDllsString
	jnz Exit
	push VerifierFlags
	push VerifierDebug
	mov eax,AVrf.pAVrfpDebug
	mov edx,AVrf.pAVrfpVerifierFlags
	mov byte ptr [ecx],0
	pop dword ptr [eax]
	pop dword ptr [edx]
; AVrfInitializeVerifier(
; 	IN ULONG Reserved,
; 	IN PCUNICODE_STRING ImagePathName,
; 	IN ULONG Flags
; 	);
	push 1
	push eax
	push eax
	Call AVrf.pAVrfInitializeVerifier
	xor eax,eax
Exit:
	ret
xAVrfInitializeVerifier endp

.data
	include Map.inc

.code
Entry proc
Local DllHandle:HANDLE
	invoke xAVrfInitializeVerifier, addr gMap, NULL, 0, 0, addr DllHandle
	jmp $
	ret
Entry endp
end Entry