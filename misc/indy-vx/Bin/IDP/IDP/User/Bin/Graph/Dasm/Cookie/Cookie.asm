; \IDP\Public\User\Bin\Graph\Dasm\Cookie\Cookie.asm
;
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; »щет адрес ntdll!_security_check_cookie().
;
NtQuerySecurityCheckCookieReference proc uses ebx esi Ip:PVOID
Local Hash[2]:DWORD
	lea eax,Hash
	xor ecx,ecx
	mov dword ptr [Hash],0B6BAC83EH	; CRC32("RtlIntegerToUnicodeString")
	mov dword ptr [Hash + 4],ecx
	push eax
	push eax
	push ecx
	push ecx
	mov eax,MI_QUERY_ENTRIES
	Call GCBE
	test eax,eax
	mov ebx,dword ptr [Hash]
	jnz Exit
	lea esi,[ebx + 80H]
Next:
	add ebx,eax
	cmp ebx,esi
	jae Error1
	push ebx
	mov eax,OP_QUERY_SIZE
	Call GCBE
	test eax,eax
	jz Error2
Check:
	cmp al,5	; call _security_check_cookie
	jne Next
	cmp byte ptr [ebx],0E8H
	jne Next
	cmp dword ptr [ebx + 5],000CC2C9H	; leave/ret 3*4
	jne Next
	add ebx,dword ptr [ebx + 1]
	mov ecx,Ip
	add ebx,5
	xor eax,eax
	mov dword ptr [ecx],ebx
Exit:
	ret
Error1:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
Error2:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
NtQuerySecurityCheckCookieReference endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; +
; »щет адрес kernel32!_security_check_cookie().
;
QuerySecurityCheckCookieReference proc uses ebx esi Ip:PVOID
Local Hash[2]:DWORD
	assume fs:nothing
	mov eax,fs:[TEB.Peb]
	xor ecx,ecx
	mov eax,PEB.Ldr[eax]
	lea edx,Hash
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
	mov dword ptr [Hash],6E698EAFH	; CRC32("CmdBatNotification")
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov dword ptr [Hash + 4],ecx
	mov ebx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	push edx
	push edx
	push 0
	push LDR_DATA_TABLE_ENTRY.DllBase[ebx]
	mov eax,MI_QUERY_ENTRIES
	Call GCBE
	test eax,eax
	lea ecx,Hash
	jz @f
	mov ebx,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[ebx]
	push ecx
	push ecx
	push 0
	push LDR_DATA_TABLE_ENTRY.DllBase[ebx]
	mov eax,MI_QUERY_ENTRIES
	Call GCBE
	test eax,eax
	jnz Exit
@@:
	mov ebx,dword ptr [Hash]
	lea esi,[ebx + 80H]
Next:
	add ebx,eax
	cmp ebx,esi
	jae Error1
	push ebx
	mov eax,OP_QUERY_SIZE
	Call GCBE
	test eax,eax
	jz Error2
Check:
	cmp al,5	; call _security_check_cookie
	jne Next
	cmp byte ptr [ebx],0E8H
	jne Next
	cmp dword ptr [ebx + 5],0004C2C9H	; leave/ret 4
	jne Next
	add ebx,dword ptr [ebx + 1]
	mov ecx,Ip
	add ebx,5
	xor eax,eax
	mov dword ptr [ecx],ebx
Exit:
	ret
Error1:
	mov eax,STATUS_NOT_FOUND
	jmp Exit
Error2:
	mov eax,STATUS_UNSUCCESSFUL
	jmp Exit
QuerySecurityCheckCookieReference endp
;~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~