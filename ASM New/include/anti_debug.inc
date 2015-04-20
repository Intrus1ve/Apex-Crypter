push ebx
push eax
push ecx
xor ebx, ebx
mov bl, 0xCC

blocStart:
	mov eax, blocStart
	mov ecx, blocEnd
	sub ecx, blocStart

antiBpLoop:
	cmp byte [eax], bl
	jne continueLoop
	mov [eax], byte 0xEB

continueLoop:
	inc eax
	dec ecx
	jnz antiBpLoop
	mov ecx, 0x02
	xor eax, eax
	jz valid
	db 0x02

valid:
	db 0xCC
	db 0x02
	ret

	db 0x81
	sub ebx, 0xB4
	mov eax, [fs:ebx]
	add ebx, ebx
	mov eax, dword [eax + ebx]
	cmp byte [eax + ecx], ch
	pop ecx
	pop eax
	pop ebx
	je blocEnd
	db 0xEA

blocEnd: