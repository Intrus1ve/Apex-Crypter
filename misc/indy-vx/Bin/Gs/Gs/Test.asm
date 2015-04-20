; Генерация Gs-серий.
; (c) Indy, 2010.
;
	.686p
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
	include Sde\Sde.inc
	include Gcbe\Gcbe.inc
	
MAX_INSTRUCTION_LENGTH	equ 15
	
PFX_LOCK	equ 0F0H
PFX_REPNZ	equ 0F2H
PFX_REP	equ 0F3H

PFX_ES		equ 26H
PFX_CS		equ 2EH
PFX_SS		equ 36H
PFX_DS		equ 3EH
PFX_FS		equ 64H
PFX_GS		equ 65H
PFX_DATA_SIZE	equ 66H
PFX_ADDR_SIZE	equ 67H

FLG_LOCK		equ 0
FLG_REPNZ		equ 1
FLG_REP		equ 2
FLG_DATA_SIZE	equ 3
FLG_ADDR_SIZE	equ 4

; Eax: Flags
; Ecx: Pfx length
; Edx: Segment
;
QueryPfxSeries proc uses ebx esi Ip:PVOID
	mov ebx,Ip
	mov esi,MAX_INSTRUCTION_LENGTH
	xor edx,edx	; Segment
	xor eax,eax
Step:
	movzx ecx,byte ptr [ebx]
	.if cl > PFX_ADDR_SIZE
	   sub cl,PFX_LOCK
	   jb Exit
	   .if !Zero?
	      dec ecx
	      jecxz Exit	; Int1
	   .endif
	   cmp cl,2
	   ja Exit
	   test al,(1 shl FLG_REP) or (1 shl FLG_REPNZ) or (1 shl FLG_LOCK)
	   jnz Abnormal
	   bts eax,ecx
	.elseif cl == PFX_DATA_SIZE
	   bts eax,FLG_DATA_SIZE
	   jc Abnormal
	.elseif cl == PFX_ADDR_SIZE
	   bts eax,FLG_ADDR_SIZE
	   jc Abnormal
	.elseif (cl == PFX_ES) || (cl == PFX_CS) || (cl == PFX_SS) || (cl == PFX_DS) || (cl == PFX_FS) || (cl == PFX_GS)
	   test edx,edx
	   jnz Abnormal
	   mov edx,ecx
	.else
Exit:
	   not esi
	   xor ebx,ebx	; CF etc.
	   lea ecx,[esi + 16]
@@:
	   ret
	.endif
	dec esi
	jz Exit
	inc ebx
	jmp Step
Abnormal:
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	sub esi,ebx	; CF & ZF.
	jmp @b
QueryPfxSeries endp

; SDE
OVSEG_DS	equ 1
OVSEG_SS	equ 2
OVSEG_ES	equ 3
OVSEG_XY	equ 4	; MOVS, CMPS(Es:[Edi], Ds:[Esi])

OP_PUSH_ES	equ 06H
OP_PUSH_SS	equ 16H
OP_PUSH_DS	equ 1EH
OP_PUSH_FS	equ 0A00FH
OP_POP_GS		equ 0A90FH

; +
; Генератор Gs-серий.
;
; o GCBE_PARSE_SEPARATE
;
GsSeriesGenerate proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID, Buffer:PVOID, IpCount:ULONG
Local OvFlags:ULONG, OvLength:ULONG, OvSegment:ULONG
Local Count:ULONG
	mov ebx,GpBase
	jmp @f
Next:
	dec Count
	jnz Step
@@:
	push IpCount
	pop Count
	test dword ptr [ebx],TYPE_MASK
	mov esi,[ebx].Address
	jnz Step	; !Line
	assume ebx:PBLOCK_HEADER
	cmp [ebx]._Size,MAX_INSTRUCTION_LENGTH
	jae Step
	invoke QueryPfxSeries, Esi
	jnz Step
	cmp edx,PFX_CS
	mov OvFlags,eax
	je Step
	cmp edx,PFX_GS
	mov OvSegment,edx
	je Step
	test eax,(1 shl FLG_DATA_SIZE)
	mov OvLength,ecx
	setnz al
	mov edi,ecx
	lea edx,[esi + ecx]
	push eax
	push edx
	Call SDE
	test eax,eax
	jz Step
	test OvFlags,(1 shl FLG_REP) or (1 shl FLG_REPNZ) or (1 shl FLG_LOCK)
	.if !Zero?
	   inc edi
	.endif
	test OvFlags,(1 shl FLG_DATA_SIZE)
	.if !Zero?
	   inc edi
	.endif
	test OvFlags,(1 shl FLG_ADDR_SIZE)
	.if !Zero?
	   inc edi
	.endif
	add edi,[ebx]._Size
	mov ecx,OvSegment
	cmp edi,MAX_INSTRUCTION_LENGTH - 1
	ja Step
	mov edi,Buffer
	test ecx,ecx
	mov edi,dword ptr [edi]
	mov edx,edi
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
; * Не формируем описатели для каждой инструкции, а обьединяем их в один блок. Это  *
; * нарушение структуры графа, так как он создан с флажком GCBE_PARSE_SEPARATE. Та  *
; * кая манипуляция не нарушит работу билдера, так как он не использует LDE. Иначе  *
; * если далее будет выполняться сторонняя обработка графа для каждой инструкции д  *
; * должна быть выполнена вставка(создан описатель). Также можно использовать LDE   *
; * для енума инструкций если граф создан с !GCBE_PARSE_SEPARATE.                   *
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	.if !Zero?
	   .if cl == PFX_ES
	      mov byte ptr [edi],OP_PUSH_ES	; Push Es
	   .elseif cl == PFX_SS
	      mov byte ptr [edi],OP_PUSH_SS	; Push Ss
	   .elseif cl == PFX_DS
	      mov byte ptr [edi],OP_PUSH_DS	; Push Ds
	   .else	; Fs
	      mov word ptr [edi],OP_PUSH_FS	; Push Fs
	      inc edi
	   .endif
	.else
	   dec eax
	   .if Zero?	; Ds
	      mov byte ptr [edi],OP_PUSH_DS	; Push Ds
	   .else
	      dec eax	; Ss
	      .if Zero?
	         mov byte ptr [edi],OP_PUSH_SS	; Push Ss
	      .else
	         dec eax	; Es
	         .if Zero?
	            mov byte ptr [edi],OP_PUSH_ES	; Push Es
	         .else	; XY
	            mov byte ptr [edi],OP_PUSH_DS	; Push Ds
	         .endif
	      .endif
	   .endif
	.endif
	test OvFlags,(1 shl FLG_ADDR_SIZE)
	mov word ptr [edi + 1],OP_POP_GS	; Pop Gs
	mov byte ptr [edi + 3],PFX_GS
	lea edi,[edi + 4]
	.if !Zero?
	   mov byte ptr [edi],PFX_ADDR_SIZE
	   inc edi
	.endif
	test OvFlags,(1 shl FLG_DATA_SIZE)
	.if !Zero?
	   mov byte ptr [edi],PFX_DATA_SIZE
	   inc edi
	.endif
	test OvFlags,FLG_LOCK
	.if !Zero?
	   mov byte ptr [edi],PFX_LOCK
	   inc edi
	.endif
	test OvFlags,(1 shl FLG_REP)
	.if !Zero?
	   mov byte ptr [edi],PFX_REP
	   inc edi
	.endif
	test OvFlags,(1 shl FLG_REPNZ)
	mov ecx,[ebx]._Size
	.if !Zero?
	   mov byte ptr [edi],PFX_REPNZ
	   inc edi
	.endif
	sub ecx,OvLength
	jbe Step
	add esi,OvLength
	cld
	mov eax,Buffer
	rep movsb
	mov dword ptr [eax],edi
	mov [ebx].Address,edx
	sub edi,edx
	mov [ebx]._Size,edi
Step:
	add ebx,ENTRY_HEADER_SIZE
	cmp GpLimit,ebx
	ja Next
	xor eax,eax
	ret
GsSeriesGenerate endp
	
%NTERR macro
	.if Eax
	Int 3
	.endif
endm

%ALLOC macro vBase, vSize, vProtect, cSize, Reg32
	mov vBase,NULL
	mov vSize,cSize
	invoke ZwAllocateVirtualMemory, NtCurrentProcess, addr vBase, 0, addr vSize, MEM_COMMIT, PAGE_READWRITE
	%NTERR
	push vBase
	add vBase,cSize - X86_PAGE_SIZE
	mov vSize,X86_PAGE_SIZE
	invoke ZwProtectVirtualMemory, NtCurrentProcess, addr vBase, addr vSize, PAGE_NOACCESS, addr vProtect
	pop Reg32
	%NTERR	
endm

GsGenerate proc Ip:PVOID, GpBase:PVOID, CsBase:PVOID, GsBuffer:PVOID, BuildBuffer:PVOID, NestingLevel:ULONG, IpCount:ULONG
Local GpLimit:PVOID
Local GsLimit:PVOID
	mov ecx,GpBase
	xor eax,eax
	lea edx,GpLimit
	mov GpLimit,ecx
	push eax
	push eax
	mov ecx,GsBuffer
	push eax
	mov GsLimit,ecx
	push eax
	push eax
	push NestingLevel
	push GCBE_PARSE_SEPARATE
	push edx
	push Ip
	%GPCALL GP_PARSE
	test eax,eax
	lea ecx,GsLimit
	jnz Exit
	invoke GsSeriesGenerate, GpBase, GpLimit, Ecx, IpCount
	push BuildBuffer
	push CsBase
	push GpLimit
	push GpBase
	%GPCALL GP_BUILD_GRAPH
Exit:
	ret
GsGenerate endp

Ep proc
Local GpBase:PVOID, GpSize:ULONG
Local CsBase:PVOID, CsSize:ULONG
Local GsBase:PVOID, GsSize:ULONG
Local BuBase:PVOID, BuSize:ULONG
Local Protect:ULONG
	%ALLOC GpBase, GpSize, Protect, 200H * X86_PAGE_SIZE, Ebx
	%ALLOC CsBase, CsSize, Protect, 200H * X86_PAGE_SIZE, Esi
	%ALLOC GsBase, GsSize, Protect, 200H * X86_PAGE_SIZE, Edi
	%ALLOC BuBase, BuSize, Protect, 10 * X86_PAGE_SIZE, Ecx
	push ecx
	invoke GsGenerate, offset GsGenerate, Ebx, Esi, Edi, Ecx, 0, 1
	%NTERR
	pop eax
	Int 3
	ret
Ep endp
end Ep