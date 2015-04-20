; Удаление(морфинг) ветвлений:
; o Jcxz
; o Jecxz
; o Loopw
; o Loopd
; o Loopwe
; o Loopde
; o Loopwne
; o Loopdne
;
Public CxMorferInitialize
Public CxMorphEntry
Public CxMorphGraph

.code
%PREGENHASH macro HashList:VARARG
Local Iter, PrevHash
   Iter = 0
   for Hash, <HashList>
      if Iter eq 0
         xor eax,eax
         sub eax,-Hash
      elseif (Iter eq 1) or (Iter eq 3)
         xor eax,(PrevHash xor Hash)
      elseif Iter eq 2
         add eax,dword ptr (Hash - PrevHash)
      elseif Iter eq 4
         sub eax,dword ptr (PrevHash - Hash)
      endif
      stosd
      Iter = Iter + 1
      PrevHash = Hash
      if Iter eq 5
         Iter = 1
      endif
   endm
endm

%POSTGENHASH macro FirstHash, HashList:VARARG
Local Iter, PrevHash
   Iter = 0
   PrevHash = FirstHash
   for Hash, <HashList>
      if (Iter eq 0) or (Iter eq 2)
         xor eax,(PrevHash xor Hash)
      elseif Iter eq 1
         add eax,dword ptr (Hash - PrevHash)
      elseif Iter eq 3
         sub eax,dword ptr (PrevHash - Hash)
      endif
      stosd
      Iter = Iter + 1
      PrevHash = Hash
      if Iter eq 4
         Iter = 0
      endif
   endm
endm

CX_GEN_STUB_LENGTH		equ ((0B6H + 11B) and NOT(11B))
CX_REPLACE_TABLE_LENGTH	equ ((077H + 11B) and NOT(11B))
CX_REPLACE_GRAPH_LENGTH	equ 920H	; * GCBE_PARSE_SEPARATE

; +
; Загрузка таблиц и создание графа.
;
; Buffer:
;	REPLACE_TABLE[CX_REPLACE_TABLE_LENGTH]
;	REPLACE_GRAPH[CX_REPLACE_GRAPH_LENGTH]
;
; o x32_CxReplaceTable[JccType * HEADER_SIZE * 2]
; o x16_CxReplaceTable = x32_CxReplaceTable + HEADER_SIZE
; o JccHeader = XX_BRANCH_HEADER.BranchLink[CxReplaceTable]
;
CxMorferInitialize proc uses edi Buffer:PVOID
Local Graph:PVOID
	mov edi,Buffer
	cld
	lea ecx,[edi + CX_REPLACE_TABLE_LENGTH]
; 0xB6
%PREGENHASH 01C740F74H, \
	037742A74H, \
	04C744574H, \
	05C745474H, \
	0498D9CC3H, \
	0850774FFH, \
	09D0374C9H, \
	0C39DE0FFH, \
	07449669CH, \
	02404F609H, \
	09D037440H, \
	0C39DE0FFH, \
	0FF498D9CH
%POSTGENHASH 0FF498D9CH, \
	0C9850775H, \
	0FF9D0374H, \
	09CC39DE0H, \
	009744966H, \
	0402404F6H, \
	0FF9D0375H, \
	09CC39DE0H, \
	09D037449H, \
	0C39DE0FFH, \
	07449669CH, \
	0E0FF9D03H, \
	0859CC39DH, \
	09D0375C9H
%POSTGENHASH 09D0375C9H, \
	0C39DE0FFH, \
	0C985669CH, \
	0FF9D0375H, \
	090C39DE0H
; -
	xor eax,eax
	mov Graph,ecx
	invoke GpParse, Buffer, addr Graph, GCBE_PARSE_SEPARATE or GCBE_PARSE_IPCOUNTING, Eax, Eax, Eax, Eax, Eax, Eax
	ret
CxMorferInitialize endp

; +
; Морфинг одного описателя.
;
; o AF сохраняется.
;
CxMorphEntry proc uses ebx esi edi Buffer:PVOID, JcxEntry:PVOID, GpLimit:PVOID
Local JcxHeader:XX_BRANCH_HEADER
Local McDelta:ULONG, SrcEntry:PVOID
	mov esi,JcxEntry
	lea edi,JcxHeader
	mov ecx,ENTRY_HEADER_SIZE/4
	mov eax,esi
	cld
	mov ebx,Buffer
	rep movsd
	mov ecx,dword ptr [eax + EhEntryType]
	and ecx,TYPE_MASK
	cmp cl,HEADER_TYPE_JCC
	mov edx,dword ptr [ebx + EhAccessFlag]
	jne Error
	test dword ptr [eax + EhJcxType],BRANCH_CX_FLAG
	jz Error
	mov eax,dword ptr [eax + EhJccType]
	and eax,JCC_TYPE_MASK
	and edx,ACCESSED_MASK_FLAG
	shl eax,5	; x ENTRY_HEADER_SIZE
	lea eax,[ebx + 2 * eax + CX_REPLACE_TABLE_LENGTH]
	test dword ptr [esi - ENTRY_HEADER_SIZE + EhJccType],JCC_X16_MASK
	.if !Zero?
	add eax,ENTRY_HEADER_SIZE
	.endif
	mov esi,dword ptr [eax + EhBranchLink]
	mov edi,JcxEntry
	and esi,NOT(TYPE_MASK)
	mov ebx,edi
	mov SrcEntry,esi
	mov eax,dword ptr [edi + EhBlink]
	cld
	and eax,NOT(TYPE_MASK)	; Blink
; 1'st: Line(pushfd).
	mov ecx,ENTRY_HEADER_SIZE/4
	or eax,edx	; AccessFlag
	rep movsd
	mov dword ptr [ebx + EhBlink],eax
	mov edi,GpLimit
	mov edi,dword ptr [edi]
	mov dword ptr [ebx + EhFlink],edi
	mov eax,edi
	sub eax,esi
	mov McDelta,eax
Ip:
; Edx: AF
; Esi: Src
; Edi: Dst
; Ebx: Prev dst.
	mov eax,dword ptr [esi + EhEntryType]
	mov ecx,ENTRY_HEADER_SIZE/4
	and eax,TYPE_MASK
	.if Zero?	; Line
	   cmp dword ptr [esi + EhFlink],NULL
	   .if Zero?
	      ; %HALT
	      mov ecx,JcxHeader.Link.Flink
	      and dword ptr [ebx + EhFlink],TYPE_MASK
	      and ecx,NOT(TYPE_MASK)
	      mov edx,GpLimit
	      or dword ptr [ebx + EhFlink],ecx
	      mov dword ptr [edx],edi
	      and dword ptr [ecx + EhBlink],TYPE_MASK
	      xor eax,eax
	      or dword ptr [ecx + EhBlink],ebx
	      jmp Exit
	   .else
	      mov ebx,edi
   	      rep movsd
   	      and dword ptr [ebx + EhFlink],TYPE_MASK
   	      or dword ptr [ebx + EhFlink],edi
	      jmp xBlink
	   .endif
	.else
	sub al,HEADER_TYPE_JMP
	.if Zero?
	; Jxx, %LINK
	   mov eax,JcxHeader.BranchLink
	   mov ebx,edi
	   and eax,NOT(TYPE_MASK)
	   rep movsd
	   mov dword ptr [ebx + EhBranchLink],eax
	   mov ecx,JcxHeader.BranchAddress
	   mov dword ptr [ebx + EhBranchAddress],ecx
xBlink:
	   mov eax,dword ptr [esi - ENTRY_HEADER_SIZE + EhBlink]
	   and eax,NOT(TYPE_MASK)
	   .if !Zero?
	      .if Eax == SrcEntry
	    	    mov eax,JcxEntry
	    	 .else
	         add eax,McDelta	; - src + dst
	      .endif
	   .endif
	   or eax,edx	; AccessFlag
	   or eax,BRANCH_DEFINED_FLAG
	   mov dword ptr [ebx + EhBlink],eax
	   jmp Ip
	.else
;	   dec al
;	   jnz Error	; Call
; Jcc
	   mov eax,dword ptr [esi + EhBlink]
	   mov ebx,edi
	   and eax,NOT(TYPE_MASK)
	   .if !Zero?
	      add eax,McDelta
	   .endif
	   rep movsd
	   mov ecx,dword ptr [ebx + EhFlink]
	   or eax,edx
	   and ecx,NOT(TYPE_MASK)
	   .if !Zero?
	      add ecx,McDelta
	   .endif
	   or cl,HEADER_TYPE_JCC
	   mov dword ptr [ebx + EhBlink],eax
	   mov dword ptr [ebx + EhFlink],ecx
	   mov eax,dword ptr [ebx + EhBranchLink]
	   and eax,NOT(TYPE_MASK)
	   add eax,McDelta
	   mov dword ptr [ebx + EhBranchLink],eax
	   jmp Ip
	   .endif
	.endif
Exit:
	ret
Error:
	mov eax,STATUS_INVALID_PARAMETER
	jmp Exit
CxMorphEntry endp

; +
; Морфинг всех описателей Jcx.
;
CxMorphGraph proc uses ebx esi edi ReplaceTable:PVOID, GpBase:PVOID, GpLimit:PVOID
Local GraphLimit:PVOID
	mov esi,GpLimit
	mov ebx,GpBase
	mov edi,dword ptr [esi]
	invoke CxMorferInitialize, ReplaceTable
	test eax,eax
	mov GraphLimit,edi
	jnz Exit
@@:
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	.if !Zero?
	   dec eax
	   .if !Zero?	; Jxx/Jcc
	      and dword ptr [ebx + EhBranchLink],NOT(TYPE_MASK)	; * Для оптимизатора Size & Idle.
	      dec eax
	      .if !Zero?	; Jcc
	         invoke CxMorphEntry, ReplaceTable, Ebx, addr GraphLimit
	      .endif
	   .endif
	.endif
	add ebx,ENTRY_HEADER_SIZE
	cmp ebx,edi
	jb @b
	mov ecx,GraphLimit
	xor eax,eax
	mov dword ptr [esi],ecx
Exit:
	ret
CxMorphGraph endp