; Вставка и удаление описателей.
; В данной модели графа имеется серьёзный недостаток - он должен быть 
; линейным(все описатели располагаться последовательно в памяти). Лин
; кование описателя за пределами графа приведёт к #AV. Таким образом 
; описатель должен добавляться в конец графа. Проблема решается конве
; ртацией графа в линейный (GP_MERGE).

; +
; Редирект BranchLink.
;
; Esi: GpBase
; Edi: GpLimit
;
RedirectAllBranchLinksInternal proc Gp:PVOID, Link:PVOID
	mov edx,esi
Check:
	cmp edi,edx
	mov eax,dword ptr [edx + EhEntryType]
	jbe Exit
	and eax,TYPE_MASK
	jz Next	; Line
	cmp al,HEADER_TYPE_JCC
	mov ecx,dword ptr [edx + EhBranchLink]
	.if !Zero?	; Call/Jxx
	   test dword ptr [edx + EhBranchType],BRANCH_DEFINED_FLAG
	   jz Next
	   dec eax
	   .if Zero?	; Call
	      test dword ptr [edx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	      jz Next
	   .endif
	.endif
	and ecx,NOT(TYPE_MASK)
	cmp Gp,ecx
	jne Next
	mov ecx,Link
	and dword ptr [edx + EhBranchLink],TYPE_MASK
	or dword ptr [edx + EhBranchLink],ecx
Next:
	add edx,ENTRY_HEADER_SIZE
	jmp Check
Exit:
	xor eax,eax
	ret
RedirectAllBranchLinksInternal endp

RedirectAllBranchLinks proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID, Gp:PVOID, Link:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov esi,GpBase
	mov edi,GpLimit
	invoke RedirectAllBranchLinksInternal, Gp, Link
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
RedirectAllBranchLinks endp

; +
; Удаление описателя из графа.
;
; I, (J), K
; J = I.Flink
; K = J.Flink
; J = K.Blink
; I = J.Blink
; -
; I.Flink -> K
; K.Blink -> I
; J.Blink.Flink -> J.Flink
; J.Flink.Blink -> J.Blink
; RedirectAllBranchLinks(J, K)
;
; o Если удаляется процедурное ветвление, то часть графа по ссылке не удаляем.
; o Безусловное ветвление не может быть удалено(так как оно завершает ветвь).
;
RwUnlinkEntry proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID, Gp:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,Gp	; [J]
	mov esi,GpBase
	mov ecx,dword ptr [ebx + EhEntryType]
	mov edi,GpLimit
	and cl,TYPE_MASK
	cmp cl,HEADER_TYPE_JMP
	je Error
	mov edx,dword ptr [ebx + EhBlink]	; [I]
	mov eax,dword ptr [ebx + EhFlink]	; [K]
	and edx,NOT(TYPE_MASK)
	and eax,NOT(TYPE_MASK)
	.if !Zero?
	   and dword ptr [eax + EhBlink],TYPE_MASK
	   or dword ptr [eax + EhBlink],edx
	.endif
	test edx,edx
	.if !Zero?
	   and dword ptr [edx + EhFlink],TYPE_MASK
	   or dword ptr [edx + EhFlink],eax
	.endif
	.if cl == HEADER_TYPE_JCC
	   or dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	.endif
	invoke RedirectAllBranchLinksInternal, Ebx, Eax
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
Error:
	mov eax,STATUS_INVALID_PARAMETER
	jmp Exit
RwUnlinkEntry endp

; +
; Вставка описателя перед текущим.
;
; I, (J), K
; J.Flink -> K
; J.Blink -> K.Blink
; K.Blink -> J
; K.Blink.Flink -> J
;
RwInsertHeadEntry proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID, CurrentGp:PVOID, NewGp:PVOID
	Call SEH_Epilog_Reference
	Call SEH_Prolog
	mov ebx,NewGp	; [J]
	mov esi,GpBase
	mov edi,GpLimit
	mov eax,CurrentGp	; [K]
	and dword ptr [ebx + EhFlink],TYPE_MASK
	and dword ptr [ebx + EhBlink],TYPE_MASK
	or dword ptr [ebx + EhFlink],eax
	and eax,NOT(TYPE_MASK)
	.if !Zero?
	   mov ecx,dword ptr [eax + EhBlink]
	   and ecx,NOT(TYPE_MASK)
	   or dword ptr [ebx + EhBlink],ecx
	   and dword ptr [eax + EhBlink],TYPE_MASK
	   or dword ptr [eax + EhBlink],ebx
	   .if Ecx
	      and dword ptr [ecx + EhFlink],TYPE_MASK
	      or dword ptr [ecx + EhFlink],ebx
	   .endif
	.endif
	invoke RedirectAllBranchLinksInternal, Eax, Ebx
	jmp Exit
SEH_Epilog_Reference:
	%GET_CURRENT_GRAPH_ENTRY
Exit:
	Call SEH_Epilog
	ret
RwInsertHeadEntry endp