;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; Определяет размер инструкции.
;
QueryOpcodeSize proc uses esi Opcode:PVOID
	mov esi,Opcode
	include VirXasm32b.asm
	ret
QueryOpcodeSize endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~