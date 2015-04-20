use32

format binary

include 'win32a.inc'
include 'pe.inc'

struct stAPITable
 pVirtualAllocEx_kernel32		 dd ?
 pLoadLibraryA_kernel32 		 dd ?
 pVirtualProtect_kernel32		 dd ?
ends

proc _GetDeltaProc, pPEImage
    stdcall	RunPE_main, [pPEImage]
    .Delta:
    ret
endp

proc	RunPE_main pPEImage
  local   pFileHeader:DWORD
  local   pNewPEPlace:DWORD
  local   APITable[0x14]:BYTE
  local   pAPITable:DWORD
  local   iResult:DWORD
  local   huser32:DWORD
  local   szuser32[0xb]:BYTE
  local   pGetHashSz:DWORD
  local   hkernel32:DWORD
  
    push    edi
    push    ecx
    push    eax
    mov     eax, [ebp+04h]
    sub     eax, _GetDeltaProc.Delta
    push    eax
    pop     ebx
    lea     ebx, [ebx+GetHashSz]
    push    ebx
    pop     DWord [pGetHashSz]
    call    GetK32
    mov     DWord [hkernel32], eax
    stdcall AltGetProcAddressByHash, [hkernel32], ebx, 0x632466f0
    mov     DWord [APITable+stAPITable.pVirtualAllocEx_kernel32], eax
    stdcall AltGetProcAddressByHash, [hkernel32], ebx, 0x15f8ef80
    mov     DWord [APITable+stAPITable.pVirtualProtect_kernel32], eax
    stdcall AltGetProcAddressByHash, [hkernel32], ebx, 0x71e40722
    mov     DWord [APITable+stAPITable.pLoadLibraryA_kernel32], eax
    lea     ecx, [APITable]
    mov     DWord [pAPITable], ecx
    stdcall verifyPE, [pPEImage]
    cmp     eax, 0x0
    jz	    .End    
    push    eax
    pop     DWord [pFileHeader]
    stdcall DWord [APITable+stAPITable.pVirtualAllocEx_kernel32], -1, NULL, DWord [eax+IMAGE_OPTIONAL_HEADER32.SizeOfImage+sizeof.IMAGE_FILE_HEADER],\
	    MEM_COMMIT or MEM_RESERVE or MEM_TOP_DOWN, PAGE_READWRITE
    mov     [pNewPEPlace], eax
    stdcall loadFile, [pAPITable], [pFileHeader], [pPEImage], [pNewPEPlace]
    stdcall loadImportTable, [pAPITable], [pGetHashSz], [pNewPEPlace]
    test    eax, eax
    jz	    .End
    stdcall reloc_fixup, [pNewPEPlace], [pFileHeader]
    stdcall setPermissions, [pAPITable], [pFileHeader], [pPEImage], [pNewPEPlace]
    mov     esi, [pFileHeader]
    mov     eax, [esi+sizeof.IMAGE_FILE_HEADER+IMAGE_OPTIONAL_HEADER32.AddressOfEntryPoint]
    add     eax, [pNewPEPlace]
    jmp     eax
.End:
    pop     eax
    pop     ecx
    pop     edi
    mov     eax, DWord [iResult]
    ret
endp

proc	verifyPE pImagePE
  local   iResult:DWORD
    pusha
    push    DWord [pImagePE]
    pop     edx
    cmp     Word [edx], WORD 0x5a4d
    jnz     .Exit
    mov     ecx, DWord [edx+IMAGE_DOS_HEADER.e_lfanew]
    add     edx, ecx
    cmp     DWord [edx], DWORD 0x4550
    jne     .Exit
    lea     edx, [edx+0x4]
.Exit:
    mov     DWord [iResult], edx
    popa
    push    DWord [iResult]
    pop     eax
    ret
endp

proc loadSection pImageSectionHeader:DWORD, pImageBase:DWORD, pBase:DWORD

    pushad 
    mov 	edx, [pImageSectionHeader]
    mov 	esi, [pImageBase]
    add 	esi, [edx+IMAGE_SECTION_HEADER.PointerToRawData]
    mov 	edi, [edx+IMAGE_SECTION_HEADER.VirtualAddress]
    add 	edi, [pBase]
    mov 	ecx, [edx+IMAGE_SECTION_HEADER.SizeOfRawData]
    cld
    rep 	movsb
    popad
    ret
endp

proc  loadFile pAPITable:DWORD, pImageFileHeader:DWORD, pImageBase, pBase:DWORD

local .iSectNum:DWORD, .pImageBase:DWORD, .pImageOptionalHeader:DWORD,	.pSectionHeaders:DWORD, .iPEHeaderSize:DWORD

    pushad
    mov 	edx, [pImageFileHeader]
    movzx	eax, Word [edx+IMAGE_FILE_HEADER.NumberOfSections]
    mov 	[.iSectNum], eax 
    lea 	edx, [edx+sizeof.IMAGE_FILE_HEADER]
    lea 	ebx, [edx + IMAGE_OPTIONAL_HEADER32.DataDirectory]
    mov 	eax, [edx + IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
    mov 	edx, sizeof.IMAGE_DATA_DIRECTORY
    mul 	edx
    add 	eax, ebx
    mov 	[.pSectionHeaders], eax
    mov 	eax, sizeof.IMAGE_SECTION_HEADER
    mov 	edx, [.iSectNum]
    mul 	edx
    add 	eax, [.pSectionHeaders]
    sub 	eax, [pImageBase]
    mov 	ecx, eax
    mov 	edi, [pBase]
    mov 	esi, [pImageBase]
    rep 	movsb
    mov 	ecx, [.iSectNum]
    mov 	ebx, [.pSectionHeaders]
.load_section_loop:
    stdcall	loadSection, ebx, [pImageBase], [pBase]
    add 	ebx, sizeof.IMAGE_SECTION_HEADER
    dec 	ecx
    jnz 	.load_section_loop
.Exit:
    popad
    ret
endp 

proc setPermissions APITable:DWORD, pImageFileHeader:DWORD, pImageBase:DWORD, pBase:DWORD

 local .number_of_sections:DWORD, .image_base:DWORD, .section_headers:DWORD, .pe_header_size:DWORD, .vprotect_ret:DWORD, .retval:DWORD

    pushad
    xor 	eax, eax
    mov 	[.retval], eax
    mov 	edx, [pImageFileHeader]
    movzx	eax, Word [edx+IMAGE_FILE_HEADER.NumberOfSections]
    mov 	[.number_of_sections], eax
    add 	edx, sizeof.IMAGE_FILE_HEADER
    mov 	eax, [edx+IMAGE_OPTIONAL_HEADER32.ImageBase]
    mov 	[.image_base], eax
    lea 	ebx, [edx+IMAGE_OPTIONAL_HEADER32.DataDirectory]
    mov 	eax, [edx+IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes]
    mov 	edx, sizeof.IMAGE_DATA_DIRECTORY
    mul 	edx
    add 	eax, ebx
    mov 	[.section_headers], eax
    mov 	eax, sizeof.IMAGE_SECTION_HEADER
    mov 	edx, [.number_of_sections]
    mul 	edx
    add 	eax, [.section_headers]
    mov 	ebx, [pImageBase]
    sub 	eax, ebx
    mov 	[.pe_header_size], eax
    mov 	edx, [APITable]
    lea 	eax, [.vprotect_ret]
    stdcall	dword [edx+stAPITable.pVirtualProtect_kernel32], [pBase], [.pe_header_size], PAGE_READONLY, eax
    test	eax, eax
    jz		.exit
    mov 	ecx, [.number_of_sections]
    mov 	ebx, [.section_headers]
.load_section_loop:
    stdcall	setSection, [APITable], ebx, [pBase], [pImageBase]
    test	eax, eax
    jz		.exit
    add 	ebx, sizeof.IMAGE_SECTION_HEADER
    loop	.load_section_loop
    inc 	[.retval]
.exit:
    popad
    mov 	eax, [.retval]
    ret
endp

proc setSection APITable:DWORD, pSectionHeader:DWORD, pBase:DWORD, pImageBase:DWORD
local .section_flags:DWORD, .retval:DWORD, .vprotect_ret:DWORD
    pushad
    xor 	ebx, ebx
    mov 	[.retval], ebx
    mov 	edx, [pSectionHeader]
;section execute/read/write?
    mov 	ebx, [edx+IMAGE_SECTION_HEADER.Characteristics]
    and 	ebx, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    cmp 	ebx, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    jne 	.no_execute_read_write
    mov 	eax, PAGE_EXECUTE_READWRITE
    mov 	[.section_flags],eax
    jmp 	.set_memory
.no_execute_read_write:
    mov 	ebx, [edx+IMAGE_SECTION_HEADER.Characteristics]
    and 	ebx, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
    cmp 	ebx, IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
    jne 	.no_execute_read
    mov 	eax, PAGE_EXECUTE_READ
    mov 	[.section_flags],eax
    jmp 	.set_memory
.no_execute_read:
    mov 	ebx, [edx+IMAGE_SECTION_HEADER.Characteristics]
    and 	ebx, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    cmp 	ebx, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
    jne 	.no_read_write
    mov 	eax, PAGE_READWRITE
    mov 	[.section_flags], eax
    jmp 	.set_memory
.no_read_write:
    mov 	ebx, [edx+IMAGE_SECTION_HEADER.Characteristics]
    and 	ebx, IMAGE_SCN_MEM_READ
    cmp 	ebx, IMAGE_SCN_MEM_READ
    jne 	.no_read
    mov 	eax, PAGE_READONLY
    mov 	[.section_flags], eax
    jmp 	.set_memory
.no_read:
    mov 	eax, PAGE_NOACCESS
    mov 	[.section_flags],eax
.set_memory:
    mov 	edx, [pSectionHeader]
    mov 	eax, [edx + IMAGE_SECTION_HEADER.VirtualAddress]
    add 	eax, [pBase]
    mov 	ecx, [APITable]
    lea 	edi, [.vprotect_ret]
    stdcall	DWord [ecx + stAPITable.pVirtualProtect_kernel32], eax, [edx + IMAGE_SECTION_HEADER.VirtualSize], [.section_flags], edi
    test	eax, eax
    jz		.Exit
    inc 	[.retval]
.Exit:
    popad
    mov 	eax, [.retval]
    ret
endp

proc	GetNtdll 
  local   iResult:DWORD
    push    edi
    push    esi
    push    ebx
    push    DWord [fs:0x30]
    pop     edi
    mov     esi, DWord [edi+0xC]
    push    DWord [esi+0x1C]
    pop     ebx
    push    DWord [ebx+0x8]
    pop     DWord [iResult]
    pop     ebx
    pop     esi
    pop     edi
    mov     eax, DWord [iResult]
    ret
endp

proc	GetK32 
  local   iResult:DWORD
    pusha
    mov     ecx, DWord [fs:0x30]
    mov     edi, DWord [ecx+0xC]
    mov     edi, DWord [edi+0x1C]
.NextModule:
    push    DWord [edi+0x8]
    pop     DWord [iResult]
    push    DWord [edi+0x20]
    pop     ebx
    mov     edi, DWord [edi]
    movzx   eax, Byte [ebx+0x18]
    test    eax, eax
    jne     .NextModule
    movzx   eax, Byte [ebx]
    cmp     eax, 0x4b
    je	    .Found_K32
    cmp     eax, 0x6b
    jne     .NextModule
.Found_K32:
    popa
    push    DWord [iResult]
    pop     eax
    ret
endp

proc	GetHashSz strz
    push    edx
    push    ecx
    mov     edx, DWord [strz]
    push    DWORD 0x0
    pop     ecx
    push    ecx
.CalcHash:
    ror     ecx, 7
    xor     [esp], ecx
    mov     cl, Byte [edx]
    lea     edx, [edx+0x1]
    test    cl, cl
    jnz     .CalcHash
    pop     eax
    pop     ecx
    pop     edx
    ret
endp

proc	AltGetProcAddressByHash hLib, fHashProc, iHashVal
  local   iResult:DWORD
    pusha
    push    DWORD 0x0
    pop     DWord [iResult]
    push    DWord [hLib]
    pop     esi
    movzx   ecx, Word [esi]
    cmp     ecx, 0x5a4d
    jne     .End
    movzx   edi, Word [esi+0x3c]
    add     edi, esi
    cmp     DWord [edi], DWORD 0x4550
    jne     .End
    push    DWord [edi+0x78]
    pop     ecx
    add     ecx, esi
    mov     ebx, DWord [ecx+0x18]
    push    ecx
    push    0x0
    pop     edx
    push    DWord [ecx+0x20]
    pop     eax
    lea     eax, [esi+eax]
.MainLoop:
    push    DWord [eax]
    pop     edi
    add     edi, esi
    push    eax
    stdcall [fHashProc], edi
    cmp     eax, DWord [iHashVal]
    pop     eax
    jz	    .FoundProcname
    lea     eax, [eax+0x4]
    lea     edx, [edx+0x1]
    sub     ebx, 0x1
    or	    ebx, ebx
    jnz     .MainLoop
    pop     ecx
    jmp     .End
.FoundProcname:
    pop     edi
    shl     edx, 1
    add     edx, DWord [edi+0x24]
    movzx   eax, Word [edx+esi]
    shl     eax, 2
    add     eax, esi
    add     eax, DWord [edi+0x1C]
    mov     ebx, DWord [eax]
    lea     ebx, [esi+ebx]
    push    ebx
    pop     DWord [iResult]
.End:
    popa
    push    DWord [iResult]
    pop     eax
    ret
endp


xReloc = sizeof.IMAGE_FILE_HEADER+IMAGE_OPTIONAL_HEADER32.DataDirectory+0x8*IMAGE_DIRECTORY_ENTRY_BASERELOC

proc reloc_fixup, dwImageBase:DWORD, pImageFileHeader:DWORD
	pusha
	mov	edx, [dwImageBase]
	mov	ebx, [pImageFileHeader]
	mov	ebx, [ebx + sizeof.IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER32.ImageBase]
	sub	edx, ebx		; edx -> reloc_correction // delta_ImageBase
	je	.end
	test	ebx, ebx
	jz	.end
	mov	eax, [pImageFileHeader]
	mov	ebx, [eax+xReloc]
	add	ebx, [dwImageBase]
.block:
	mov	eax, [ebx + 04h]	; ImageBaseRelocation.SizeOfBlock
	test	eax, eax
	jz	.end
	lea	ecx, [eax - 008h]
	shr	ecx, 001h
	lea	edi, [ebx + 008h]
.do_entry:
	movzx	eax, word [edi] 	; Entry
	push	edx
	mov	edx, eax
	shr	eax, 00Ch		; Type = Entry >> 12
	mov	esi, [dwImageBase]	; ImageBase
	and	dx,  0FFFh
	add	esi, [ebx]
	add	esi, edx
	pop	edx
.HIGH:					; IMAGE_REL_BASED_HIGH  
	dec	eax
	jnz	.LOW
	mov	eax, edx
	shr	eax, 010h		; HIWORD(Delta)
	jmp	.LOW_fixup	  
.LOW:					; IMAGE_REL_BASED_LOW 
	dec	eax
	jnz	.HIGHLOW
	movzx	eax, dx 		; LOWORD(Delta)
.LOW_fixup:
	add	word [esi], ax		; mem[x] = mem[x] + delta_ImageBase
	jmp	.next_entry		
.HIGHLOW:				; IMAGE_REL_BASED_HIGHLOW
	dec	eax
	jnz	.next_entry
	add	[esi],edx		; mem[x] = mem[x] + delta_ImageBase
.next_entry:
	inc	edi
	inc	edi			; Entry++
	loop	.do_entry
.next_base:
	add	ebx, [ebx + 004h]
	jmp	.block
.end:
	popa
	ret
endp

proc loadImportTable APITable:DWORD, pHashProc:DWORD, image_base:DWORD

local .import_table:DWORD, .null_directory_entry[sizeof.IMAGE_IMPORT_DESCRIPTOR]:BYTE, .retval:DWORD

    pushad
    xor 	eax, eax
    inc 	eax
    mov 	[.retval], eax
    mov 	edx, [image_base]
    mov 	eax, [edx + IMAGE_DOS_HEADER.e_lfanew]
    lea 	eax, [edx + eax + 4 + sizeof.IMAGE_FILE_HEADER+IMAGE_OPTIONAL_HEADER32.DataDirectory+sizeof.IMAGE_DATA_DIRECTORY]
    mov 	eax, [eax+IMAGE_DATA_DIRECTORY.VirtualAddress]
    add 	eax, edx
    mov 	[.import_table],eax
    lea 	edi, [.null_directory_entry]
    mov 	ecx, sizeof.IMAGE_IMPORT_DESCRIPTOR
    mov 	al, 0h
    rep 	stosb
    mov 	ebx, [.import_table]
.next_directory_entry:
    lea 	esi, [.null_directory_entry]
    mov 	edi, ebx
    mov 	ecx, sizeof.IMAGE_IMPORT_DESCRIPTOR
    rep 	cmpsb
    je		.exit_success
    stdcall	loadImportDirectoryTable, [APITable], [pHashProc], [image_base], ebx
    test	eax, eax
    jz		.exit_error
    add 	ebx, sizeof.IMAGE_IMPORT_DESCRIPTOR
    jmp 	.next_directory_entry
.exit_success:
    inc 	[.retval]
.exit_error:
    popad
    mov 	eax, [.retval]
    ret
endp

proc loadImportDirectoryTable APITable:DWORD, pHashProc:DWORD, image_base:DWORD, directory_entry:DWORD

  local .lookup_table:DWORD, .import_address_table:DWORD, .dll_image_base:DWORD
    pushad
    mov 	eax, [directory_entry]
    mov 	eax, [eax+IMAGE_IMPORT_DESCRIPTOR.Name_]
    add 	eax, [image_base]
    ;load the corresponding dll
    mov 	ebx, [APITable]
    stdcall	DWord [ebx+stAPITable.pLoadLibraryA_kernel32], eax
    test	eax,eax
    jz		.exit_error
    mov 	[.dll_image_base],eax
    mov 	edx, [directory_entry]
    mov 	eax, [edx+IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
    add 	eax, [image_base]
    mov 	[.lookup_table], eax
    mov 	eax, [edx+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
    add 	eax, [image_base]
    mov 	[.import_address_table],eax
    xor 	ecx, ecx

.next_lookup_entry:
    mov 	eax, [.lookup_table]
    add 	eax, ecx
    mov 	eax, [eax]
    test	eax,eax
    jz		.exit_success
    mov 	ebx, eax
    and 	eax, IMAGE_ORDINAL_FLAG32
    jnz 	.exit_error
.byname:
    add 	ebx, [image_base]
    lea 	ebx, [ebx+IMAGE_IMPORT_BY_NAME.Name_]
    mov 	eax, ebx
    push	ecx
    stdcall	GetHashSz, ebx
    stdcall	AltGetProcAddressByHash, [.dll_image_base], [pHashProc], eax
    pop 	ecx
    test	eax, eax
    jz		.exit_error
    mov 	ebx, [.import_address_table]
    add 	ebx, ecx
    mov 	[ebx], eax
    add 	ecx, 4
    jmp 	.next_lookup_entry
.exit_success:
    popad
    mov eax,1
    ret
.exit_error:
    popad
    mov eax,0
    ret
endp

dd _GetDeltaProc