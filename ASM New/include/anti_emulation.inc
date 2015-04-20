emul:
	push 74394h
	call iswalpha ;ecx = 103h
	mov eax, 103h
	sub eax, ecx
	add eax, cont
	jmp eax

exit:
	xor ecx, ecx
	large:
		xor eax, eax
		cmp ecx, 0x7FFFFFFF
		jl large
	push 0
	call ExitProcess

cont: