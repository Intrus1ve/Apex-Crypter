_strcmp@8:
	push ebp
	mov ebp, esp
	mov eax, [ebp + 8]
	mov ecx, [ebp + 12]
	sub esp, 1
	.cmploop:
		mov [ebp - 1], STR_INEQUAL
		mov dl, [eax]
		mov dh, [ecx]
		cmp dl, dh
		jne .funcret
		mov [ebp - 1], STR_EQUAL
		test dl, dl
		jz .funcret
		inc eax
		inc ecx
		jmp .cmploop
	.funcret:
		cmp [ebp - 1], STR_EQUAL
		mov esp, ebp
		pop ebp
		ret 8