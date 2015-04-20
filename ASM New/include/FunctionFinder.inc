FindFunctionAddresses:
	push ebp
	mov ebp, esp
	push eax
	mov eax, [eax + LDR_MODULE.DllBase]
	mov ecx, [eax + DOS_HEADER.e_lfanew]
	add ecx, eax
	mov ecx, [ecx + NT_HEADER.OptionalHeader + OPTIONAL_HEADER.DataDirectories]
	add ecx, eax
	mov ebx, 0
	.loopnames:
		mov edx, [ecx + 20h]
		add edx, eax
		mov edx, [edx + (ebx * 4)]
		add edx, eax
		push ebx
		mov ebx, 0
		.loopfunctions:
			mov edi, [FunctionEntries + (ebx * 8)]
			strcmp(edi, edx)
			jne .continue
				pop edi
				push edi
				push ecx
				push esi
				mov edx, [ecx + 24h]
				add edx, eax
				mov esi, [ecx + 1Ch]
				add esi, eax
				xor ecx, ecx
				mov cx, [edx + (edi * 2)]
				mov esi, [esi + (ecx) * 4]
				mov ecx, esi
				add ecx, eax
				mov esi, [FunctionEntries + (ebx * 8) + 4]
				mov [esi], ecx
				pop esi
				pop ecx
			.continue:
				inc ebx
				cmp ebx, FunctionEntries.Count
				jne .loopfunctions
		pop ebx
		inc ebx
		cmp ebx, [ecx + 18h]
		jne .loopnames
	.funcret:
		pop eax
		mov esp, ebp
		pop ebp
		ret