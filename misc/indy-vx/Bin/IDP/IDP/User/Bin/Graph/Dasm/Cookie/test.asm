; \IDP\Public\User\Bin\Graph\Dasm\Cookie\test.asm
;
	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc

BREAK macro
	int 3
endm
.code
	include ..\Dasm.inc
	include Cookie.asm

Entry proc	
Local NtCookie:PVOID
Local Cookie:PVOID
	invoke NtQuerySecurityCheckCookieReference, addr NtCookie
	.if !Eax
	invoke QuerySecurityCheckCookieReference, addr Cookie
	.if !Eax
	mov ecx,NtCookie
	mov edx,Cookie
	BREAK
	.endif
	.endif 
	ret
Entry endp
end Entry