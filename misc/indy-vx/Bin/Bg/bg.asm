Public xQueryBugCheckEnvironment

BUGCHECK_EXTERNAL_ENTRIES struct
pKeBugCheck				PVOID ?
pKeBugCheckEx				PVOID ?
pKiBugCheckData			PVOID ?
pHeadlessDispatch			PVOID ?
pInbvAcquireDisplayOwnership	PVOID ?
pInbvCheckDisplayOwnership	PVOID ?
pInbvDisplayString			PVOID ?
pInbvEnableDisplayString		PVOID ?
pInbvInstallDisplayStringFilter	PVOID ?
pInbvIsBootDriverInstalled	PVOID ?
BUGCHECK_EXTERNAL_ENTRIES ends

BUGCHECK_INTERNAL_ENTRIES struct
pKeBugCheck2				PVOID ?	; KeBugCheck()
pHeadlessGlobals			PVOID ?	; HeadlessDispatch()
pInbvBootDriverInstalled		PVOID ?	; InbvIsBootDriverInstalled()
pInbvDisplayFilter			PVOID ?	; InbvInstallDisplayStringFilter()
pInbvDisplayDebugStrings		PVOID ?	; InbvEnableDisplayString()
pInbvDisplayState			PVOID ?	; InbvCheckDisplayOwnership()
pInbvResetDisplayParameters	PVOID ?	; InbvAcquireDisplayOwnership()
BUGCHECK_INTERNAL_ENTRIES ends

BUGCHECK_BACKTRACE_ENTRIES struct
pSt$KeBugCheck$KeBugCheck2			PVOID ?	; KeBugCheck()
pSt$KeBugCheckEx$KeBugCheck2			PVOID ?	; KeBugCheckEx()
pStInbv$AcquireDisplayOwnership$ResetDisplayParameters	PVOID ?	; InbvAcquireDisplayOwnership()
pStInbv$DisplayString$DisplayFilter	PVOID ?	; InbvDisplayString()
BUGCHECK_BACKTRACE_ENTRIES ends

BUGCHECK_ENVIRONMENT struct
Ext		BUGCHECK_EXTERNAL_ENTRIES <>
Sym		BUGCHECK_INTERNAL_ENTRIES <>
Sfc		BUGCHECK_BACKTRACE_ENTRIES <>
BUGCHECK_ENVIRONMENT ends
PBUGCHECK_ENVIRONMENT typedef ptr BUGCHECK_ENVIRONMENT

; o KeBugCheck
; o KeBugCheckEx
; o KeBugCheck2
; o KiBugCheckData
; o HeadlessDispatch
; o HeadlessGlobals
; o InbvAcquireDisplayOwnership
; o InbvCheckDisplayOwnership
; o InbvDisplayString
; o InbvEnableDisplayString
; o InbvInstallDisplayStringFilter
; o InbvIsBootDriverInstalled
; o InbvBootDriverInstalled
; o InbvDisplayFilter
; o InbvDisplayDebugStrings
; o InbvDisplayState
; o InbvResetDisplayParameters
; o St$KeBugCheck$KeBugCheck2
; o St$KeBugCheckEx$KeBugCheck2
; o StInbv$AcquireDisplayOwnership$ResetDisplayParameters
; o StInbv$DisplayString$DisplayFilter

xQueryBugCheckEnvironment proc uses ebx esi edi NtImageBase:PVOID, BugEnv:PBUGCHECK_ENVIRONMENT
Local ImageHeader:PIMAGE_NT_HEADERS
Local Fn[2]:BUGCHECK_ENVIRONMENT
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov edi,NtImageBase
	invoke LdrImageNtHeader, Edi, addr ImageHeader
	test eax,eax
	lea edi,Fn.Ext
	mov ecx,sizeof(BUGCHECK_EXTERNAL_ENTRIES)/4
	jnz Exit
	push 0A3AD0FF6H	; HASH("InbvIsBootDriverInstalled")
	push 03C4F9DD4H	; HASH("InbvInstallDisplayStringFilter")
	push 098E7D9C3H	; HASH("InbvEnableDisplayString")
	push 0428C2859H	; HASH("InbvDisplayString")
	push 0596EE436H	; HASH("InbvCheckDisplayOwnership")
	push 0AF2BF06CH	; HASH("InbvAcquireDisplayOwnership")
	push 0F00CC967H	; HASH("HeadlessDispatch")
	push 03A0C560DH	; HASH("KiBugCheckData")
	push 069EFC386H	; HASH("KeBugCheckEx")
	push 00C8F2EFBH	; HASH("KeBugCheck")
	cld
	mov esi,esp
	rep movsd
	stosd
	invoke LdrEncodeEntriesList, NtImageBase, 0, addr Fn.Ext
	test eax,eax
	mov esi,Fn.Ext.pHeadlessDispatch
	mov ebx,6	; IP's
	jnz Exit
; HeadlessDispatch -> _HeadlessGlobals
@@:
	Call VirXasm32
	add esi,eax
	cmp byte ptr [esi],0A1H	; mov eax,dword ptr [_HeadlessGlobals]
	je @f
	dec ebx
	jnz @b
Error:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
@@:
	mov eax,dword ptr [esi + 1]	; _HeadlessGlobals
	mov esi,Fn.Ext.pKeBugCheck
	mov Fn.Sym.pHeadlessGlobals,eax
; KeBugCheck -> _KeBugCheck2
	lea ebx,[esi + 20H]
KeBugCheck@Step:
	Call VirXasm32
	add esi,eax
	movzx eax,byte ptr [esi]
	cmp al,0E8H	; Call KeBugCheck2
	je KeBugCheck@Call	
@@:
	cmp al,0CCH	; Int3
	je Error
	cmp al,0C2H
	je Error
	cmp esi,ebx
	jb KeBugCheck@Step
	jmp Error
KeBugCheck@Call:
	lea ecx,[esi + 5]
; InbvIsBootDriverInstalled -> _InbvBootDriverInstalled
	mov eax,Fn.Ext.pInbvIsBootDriverInstalled
	add esi,dword ptr [esi + 1]
	cmp byte ptr [eax],0A0H	; mov al,byte ptr ds:[_InbvBootDriverInstalled]
	mov Fn.Sfc.pSt$KeBugCheck$KeBugCheck2,ecx
	jne Error
	mov eax,dword ptr [eax + 1]
	add esi,5		; _KeBugCheck2
	mov Fn.Sym.pInbvBootDriverInstalled,eax
	mov Fn.Sym.pKeBugCheck2,esi
; KeBugCheckEx -> _KeBugCheck2
	mov esi,Fn.Ext.pKeBugCheckEx
	lea ebx,[esi + 20H]
KeBugCheckEx@Step:
	Call VirXasm32
	add esi,eax
	movzx eax,byte ptr [esi]
	cmp al,0E8H	; Call KeBugCheck2
	je KeBugCheckEx@Call	
@@:
	cmp al,0CCH	; Int3
	je Error
	cmp al,0C2H
	je Error
	cmp esi,ebx
	jb KeBugCheckEx@Step
	jmp Error
KeBugCheckEx@Call:
	lea ecx,[esi + 5]
	add esi,dword ptr [esi + 1]
	mov Fn.Sfc.pSt$KeBugCheckEx$KeBugCheck2,ecx
	add esi,5		; _KeBugCheck2
	mov ebx,12	; IP's
	cmp Fn.Sym.pKeBugCheck2,esi
	jne Error
	mov esi,Fn.Ext.pInbvInstallDisplayStringFilter
; InbvInstallDisplayStringFilter -> _InbvDisplayFilter
comment '	
InbvInstallDisplayStringFilter:
$		8BFF			mov edi,edi
$+2		55			push ebp
$+3		8BEC			mov ebp,esp
$+5		8B45 08		mov eax,dword ptr ss:[ebp+8]
$+8		A3 XXXXXXXX	mov dword ptr ds:[InbvDisplayFilter],eax
$+D		5D			pop ebp
$+E		C2 0400		ret 4
		'
@@:
	cmp byte ptr [esi],0A3H	; mov dword ptr ds:[_InbvDisplayFilter],eax
	je @f
	Call VirXasm32
	add esi,eax
	dec ebx
	jnz @b
	jmp Error
@@:
	mov eax,dword ptr [esi + 1]	; _InbvDisplayFilter
	mov esi,Fn.Ext.pInbvEnableDisplayString
	mov Fn.Sym.pInbvDisplayFilter,eax
; InbvEnableDisplayString -> _InbvDisplayDebugStrings
comment '
InbvEnableDisplayString:
$		8BFF			mov edi,edi
$+2		55			push ebp
$+3		8BEC			mov ebp,esp
$+5		8A4D 08		mov cl,byte ptr ss:[ebp+8]
$+8		A0 XXXXXXXX	mov al,byte ptr ds:[_InbvDisplayDebugStrings]
$+D		880D XXXXXXXX	mov byte ptr ds:[_InbvDisplayDebugStrings],cl
$+13		5D			pop ebp
$+14		C2 0400		ret 4
		'
	mov ebx,12	; IP's
@@:
	cmp byte ptr [esi],0A0H	; mov al,byte ptr ds:[_InbvDisplayDebugStrings]
	je @f
	Call VirXasm32
	add esi,eax
	dec ebx
	jnz @b
	jmp Error
@@:
	mov eax,dword ptr [esi + 1]	; _InbvDisplayDebugStrings
	mov esi,Fn.Ext.pInbvCheckDisplayOwnership
	mov Fn.Sym.pInbvDisplayDebugStrings,eax
; InbvCheckDisplayOwnership -> _InbvDisplayState
comment '
InbvCheckDisplayOwnership:
$		33C0				xor eax,eax
$+2		833D XXXXXXXX 02	cmp dword ptr ds:[_InbvDisplayState],2
$+9		0F95C0			setne al
$+C		C3				ret
		'
	mov ebx,4	; IP's
@@:
	cmp word ptr [esi],3D83H	; cmp dword ptr ds:[_InbvDisplayState],2
	je @f
	Call VirXasm32
	add esi,eax
	dec ebx
	jnz @b
	jmp Error
@@:
	mov eax,dword ptr [esi + 2]	; _InbvDisplayState
	mov esi,Fn.Ext.pInbvAcquireDisplayOwnership
	mov Fn.Sym.pInbvDisplayState,eax
; InbvAcquireDisplayOwnership -> _InbvResetDisplayParameters
comment '
InbvAcquireDisplayOwnership:
$		A1 88444800		mov eax,dword ptr ds:[_InbvResetDisplayParameters]
$+5		85C0				test eax,eax
$+7		74 0F			je short +18
$+9		833D XXXXXXXX 02	cmp dword ptr ds:[_InbvDisplayState],2
$+10		75 06			jnz short +18
$+12		6A 32			push 32
$+14		6A 50			push 50
$+16		FFD0				call eax
(pStInbv$AcquireDisplayOwnership$ResetDisplayParameters):
$+18		8325 XXXXXXXX 00	and dword ptr ds:[_InbvDisplayState],0
$+1F		C3				ret
		'
	mov ebx,12	; IP's
@@:
	cmp byte ptr [esi],0A1H	; mov eax,dword ptr ds:[_InbvResetDisplayParameters]
	je @f
	cmp byte ptr [esi],0C3H	; ret
	je Error
	Call VirXasm32
	add esi,eax
	dec ebx
	jnz @b
	jmp Error
@@:
	mov edi,dword ptr [esi + 1]	; _InbvResetDisplayParameters
	cmp word ptr [esi + 5],0C085H	; test eax,eax
	jne Error
	cmp byte ptr [esi + 7],74H	; jz XX
	jne Error
	mov ebx,10
@@:
	Call VirXasm32
	add esi,eax
	dec ebx
	jz Error
	cmp byte ptr [esi],0A1H
	je Error
	cmp word ptr [esi],0D0FFH	; call eax
	jne @b
	add esi,2
	mov Fn.Sym.pInbvResetDisplayParameters,edi
	mov Fn.Sfc.pStInbv$AcquireDisplayOwnership$ResetDisplayParameters,esi
; InbvDisplayString -> pStInbv$DisplayString$DisplayFilter
comment '
InbvDisplayString:
$		8BFF				mov edi,edi
$+2		55				push ebp
$+3		8BEC				mov ebp,esp
$+5		53				push ebx
$+6		33DB				xor ebx,ebx
$+8		381D XXXXXXXX		cmp byte ptr ds:[_InbvBootDriverInstalled],bl
$+E 		0F84 XXXXXXXX		je ..	; -> xor al,al
$+14		391D XXXXXXXX		cmp dword ptr ds:[_InbvDisplayState],ebx
$+1A		0F85 XXXXXXXX		jnz ..	; -> xor al,al
$+20		381D XXXXXXXX		cmp byte ptr ds:[_InbvDisplayDebugStrings],bl
$+26		74 40			je ..	; -> mov al,1
$+28		A1 XXXXXXXX		mov eax,dword ptr ds:[_InbvDisplayFilter]
$+2D		3BC3				cmp eax,ebx
$+2F		74 06			je short +37
$+31		8D4D 08			lea ecx,dword ptr ss:[ebp+8]
$+34		51				push ecx
$+35		FFD0				call eax
(pStInbv$DisplayString$DisplayFilter):
$+37		E8 31E1FFFF		call ntoskrnl._InbvAcquireLock@0
$+3C		FF75 08			push dword ptr ss:[ebp+8]
		'
	xor edi,edi
	mov esi,Fn.Ext.pInbvDisplayString
	lea ebx,[esi + 50H]
InbvDisplayString@Ip:
	movzx eax,word ptr [esi]
	cmp al,0A1H	; mov eax,dword ptr ds:[_InbvDisplayFilter]
	je InbvDisplayString@LoadEax
	cmp al,0C2H	; ret 4
	je Error
	cmp ax,0D0FFH	; call eax
	je InbvDisplayString@CallEax
InbvDisplayString@Step:
	Call VirXasm32
	add esi,eax
	cmp esi,ebx
	jb InbvDisplayString@Ip
	jmp Error
InbvDisplayString@LoadEax:
	mov edi,dword ptr [esi + 1]
	jmp InbvDisplayString@Step	; + 5
InbvDisplayString@CallEax:
	test edi,edi
	jz Error
	cmp Fn.Sym.pInbvDisplayFilter,edi
	jne Error
	add esi,2
	cld
	mov ecx,sizeof(BUGCHECK_ENVIRONMENT)/4
	mov Fn.Sfc.pStInbv$DisplayString$DisplayFilter,esi
	mov edi,BugEnv
	lea esi,Fn
	xor eax,eax
	rep movsd
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
xQueryBugCheckEnvironment endp