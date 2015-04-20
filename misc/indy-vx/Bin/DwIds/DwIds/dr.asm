	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
.code
	include Base.inc
DtLimit:

; +
; Извлечение идентификатора сигнатуры по имени.
;
QuerySegnatureId proc uses ebx esi edi SigName:PSTR
Local NameLength:ULONG
	xor ebx,ebx	; ID
	lea esi,Database
	cld
Scan:
	lodsb
	test al,al
	jz Next
	mov edi,SigName
@@:
	mov ah,byte ptr [edi]
	cmp al,ah
	jne @f
	test al,al
	jz Load
	inc edi
	lodsb
	jmp @b
@@:
	test al,al
	jz Next
	lodsb
	jmp @b
Next:
	inc ebx
	cmp esi,DtLimit
	jb Scan
	xor eax,eax
Exit:
	ret
Load:
	lea eax,[ebx + 1]
	jmp Exit
QuerySegnatureId endp

$Sig	db "AIDS",0

Entry proc
	invoke QuerySegnatureId, addr $Sig
	ret
Entry endp
end Entry