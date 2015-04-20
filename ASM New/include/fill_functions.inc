mov eax, __peb
mov eax, [eax + LDR]
mov eax, [eax + InLoadOrder]
mov eax, [eax] ; ntdll.dll LDR_MODULE
call FindFunctionAddresses
mov eax, [eax] ; kernel32.dll LDR_MODULE
call FindFunctionAddresses