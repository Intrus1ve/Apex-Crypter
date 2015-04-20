Public CsMarkAndUnlinkIdleBranches
;
; Удаление холостых ветвлений.
;
comment ^	o Псевдокод очистки графа от паразитных(холостых) ветвлений.
Restart:
   for Gp = GpBase to GpLimit
   if Gp.Type = JXX
      if Gp.Flags & BRANCH_DEFINED_FLAG
         if Gp.BranchLink = @Gp + SIZE(Gp)	; *
            ; Jxx $'
            > Unlink
         else
            Gp2 = Gp.BranchLink
            if Gp2.Type = JXX
               ; Jxx -> Jxx
               if Gp2.Flags & BRANCH_DEFINED_FLAG
                  > Idle
               else
                  Gp[] = Gp2[]
                  if !Gp2.Blink	; Idle
                     MarkIdle(Gp2)
                     SubstituteAllJxx(Gp2)
                  fi
               fi
               > Restart
            fi
         fi
      fi
   elseif Gp.Type = JCC
      if Gp.BranchLink = Gp.Flink
         if Gp.Flags & BRANCH_CX_FLAG
            if Gp.JccType = JCC_ECXZ
               ; Jcxz $'
               ; Jecxz $'
 Unlink:
               if Gp.Blink
                  Gp.Blink.Flink = Gp.BranchLink
               fi
               if Gp.Flink
                  Gp.Flink.Blink = Gp.BranchLink
               fi
               MarkIdle(Gp)
               RedirectAllBranchLinks(Gp, Gp.BranchLink)
               > Restart
            fi
         else
            ; Jcc $'
            > Unlink
         fi
      else
 Self:       
         Gp2 = Gp.BranchLink
         if Gp2.Type = JXX
            ; Jcc -> Jxx
            if Gp2.Flags & BRANCH_DEFINED_FLAG
 Idle:
               Gp.BranchLink = Gp2.BranchLink
               if !Gp2.Blink	; Idle
                  MarkIdle(Gp2)
                  RedirectAllBranchLinks(Gp2, Gp2.BranchLink)
               fi
               > Restart
            fi
         fi
      fi
   elseif Gp.Type = CALL
      if Gp.Flags & BRANCH_DEFINED_FLAG
         if Gp.Flags & DISCLOSURE_CALL_FLAG
            ; Call -> Jxx
            > Self
         fi
      fi
   fi
   next
   ^

; +
; Идентифицирует паразитное ветвление на следующую инструкцию.
;
; o Ebx: Jxx/Jcc!
; o Edi: GpLimit
;
IsIdleBranch proc C uses ecx
	mov ecx,ebx
	mov edx,dword ptr [ebx + EhBranchLink]
	and edx,NOT(TYPE_MASK)
@@:
	add ecx,ENTRY_HEADER_SIZE
	cmp edi,ecx
	jna Useful
	cmp ecx,edx
	je Idle
	mov eax,dword ptr [ecx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_CALL
	jbe Useful	; Line/Call
	test dword ptr [ecx + EhIdleBranch],BRANCH_IDLE_FLAG
	jz @b
Useful:
	xor eax,eax
Exit:
	ret
Idle:
	mov eax,ecx
	test eax,eax
	jmp Exit
IsIdleBranch endp

; +
; o Обработка таблицы перекрёстных ссылок(вторичный граф) для идентификации ветвлений на следующую инструкцию.
; o Перекрёстные ссылки не модифицируем(не нужны).
;
CsMarkAndUnlinkIdleBranches proc uses ebx esi edi GpBase:PVOID, GpLimit:PVOID
Restart:
	mov ebx,GpBase
	mov esi,GpBase
	mov edi,GpLimit
Step:
; Ebx: Gp
; Ecx: Gp2(BranchLink)
	mov ecx,dword ptr [ebx + EhBranchLink]
	mov eax,dword ptr [ebx + EhEntryType]
	and ecx,NOT(TYPE_MASK)
	and eax,TYPE_MASK
	jz Next	; Line
	dec eax
	jnz IsJxx
; Call
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz Next
	test dword ptr [ebx + EhDisclosureFlag],DISCLOSURE_CALL_FLAG
	jz Next
	jmp Self	; Call -> Jxx
IsJxx:
	test dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	jnz Next
	dec eax
	jnz Jcc
; Jxx
	; Jxx -> Jxx
	; Jxx $'
	test dword ptr [ebx + EhBranchType],BRANCH_DEFINED_FLAG
	jz Next
	invoke IsIdleBranch
	jnz Unlink	; Jxx $'
	mov eax,dword ptr [ecx + EhEntryType]
	and eax,TYPE_MASK
	cmp al,HEADER_TYPE_JMP
	.if Zero?
	   ; Jxx -> Jxx
	   test dword ptr [ecx + EhBranchType],BRANCH_DEFINED_FLAG
	   jnz Idle
	   mov eax,dword ptr [ecx + EhBranchLink]
	   and eax,NOT(TYPE_MASK)
	   and dword ptr [ebx + EhBranchLink],TYPE_MASK
	   mov edx,dword ptr [ecx + EhBlink]
	   or dword ptr [ebx + EhBranchLink],eax
	   and edx,NOT(TYPE_MASK)
	   .if Zero?
	      or dword ptr [ecx + EhIdleBranch],BRANCH_IDLE_FLAG
	      invoke RedirectAllBranchLinksInternal, Ecx, Eax
	   .endif
	   jmp Restart
	.endif
	jmp Next
Jcc:
	mov eax,dword ptr [ebx + EhFlink]
	and eax,NOT(TYPE_MASK)	; GCBE_PARSE_SEPARATE!
	cmp eax,ecx
	jne Self
;	invoke IsIdleBranch
;	je Self
	test dword ptr [ebx + EhJcxType],BRANCH_CX_FLAG
	mov edx,dword ptr [ebx + EhJccType]
	jz Unlink	; Jcc $'
	and edx,JCC_TYPE_MASK
	cmp dl,(JCC_ECXZ - JCX_OPCODE_BASE)
	jne Next
	; Jcxz $'
	; Jecxz $'
Unlink:
	; Blink
	mov eax,dword ptr [ebx + EhBlink]
	and eax,NOT(TYPE_MASK)
	.if !Zero?
	   and dword ptr [eax + EhFlink],TYPE_MASK
	   or dword ptr [eax + EhFlink],ecx
	.endif
	; Flink
	mov eax,dword ptr [ebx + EhFlink]
	and eax,NOT(TYPE_MASK)
	.if !Zero?
	   and dword ptr [eax + EhBlink],TYPE_MASK
	   or dword ptr [eax + EhBlink],ecx
	.endif
	or dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	invoke RedirectAllBranchLinksInternal, Ebx, Ecx
	jmp Restart
Self:
	mov eax,dword ptr [ecx + EhEntryType]
	and eax,TYPE_MASK
	.if al == HEADER_TYPE_JMP
	; Jcc -> Jxx
	   test dword ptr [ecx + EhBranchType],BRANCH_DEFINED_FLAG
	   .if !Zero?
Idle:
	      mov eax,dword ptr [ecx + EhBranchLink]
	      and eax,NOT(TYPE_MASK)
	      and dword ptr [ebx + EhBranchLink],TYPE_MASK
	      mov edx,dword ptr [ebx + EhBlink]
	      or dword ptr [ebx + EhBranchLink],eax
	      ; Blink
	      and edx,NOT(TYPE_MASK)
	      .if Zero?
	         or dword ptr [ecx + EhIdleBranch],BRANCH_IDLE_FLAG
	         invoke RedirectAllBranchLinksInternal, Ecx, Eax
	      .endif
	      jmp Restart
	   .endif
	.endif
Next:
	add ebx,ENTRY_HEADER_SIZE
	cmp edi,ebx
	ja Step
	xor eax,eax
	ret
CsMarkAndUnlinkIdleBranches endp

; +
; Обработка первичного графа для идентификации ветвлений Jcx на следующую инструкцию перед морфингом.
;
RwUnlinkJcxSelfBranches proc uses ebx GpBase:PVOID, GpLimit:PVOID
	mov ebx,GpBase
@@:
	mov eax,dword ptr [ebx + EhEntryType]
	and eax,TYPE_MASK
	cmp eax,HEADER_TYPE_JCC	; Jcc
	je Jcc
Next:
	add ebx,ENTRY_HEADER_SIZE
	cmp GpLimit,ebx
	ja @b
	xor eax,eax
	ret
Jcc:
	test dword ptr [ebx + EhJcxType],BRANCH_CX_FLAG
	je Next
	test dword ptr [ebx + EhIdleBranch],BRANCH_IDLE_FLAG
	jnz Next
	mov ecx,dword ptr [ebx + EhJccType]
	and ecx,JCC_TYPE_MASK
	cmp cl,(JCC_ECXZ - JCX_OPCODE_BASE)
	jne Next
	mov eax,dword ptr [ebx + EhFlink]
	mov ecx,dword ptr [ebx + EhBranchLink]
	and eax,NOT(TYPE_MASK)
	and ecx,NOT(TYPE_MASK)
	cmp eax,ecx
	jne Next
; o Jcxz $'
; o Jecxz $'
; Mark & Unlink.
	invoke RwUnlinkEntry, GpBase, GpLimit, Ebx
	jmp Next
RwUnlinkJcxSelfBranches endp