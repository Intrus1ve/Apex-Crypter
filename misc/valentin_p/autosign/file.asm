;-----------------------------------
szLens proc txt
mov eax,txt
.while byte ptr [eax]!=0
inc eax
.endw
sub eax,txt
ret
szLens endp
;-----------------------------------
szCmps proc txt,txt2
pushad
invoke szLens,txt
mov ebx,eax
invoke szLens,txt2
cmp eax,ebx
jne @err
mov ecx,eax
mov esi,txt
mov edi,txt2
@@:
mov al,byte ptr [esi]
cmp byte ptr [edi],al
jne @err
inc esi
inc edi
loop @B
@ok:
popad
mov eax,1
ret
@err:
popad
mov eax,0
ret
szCmps endp
;-----------------------------------
Create_file proc name_
invoke CreateFileA,name_,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,0,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0 
ret
Create_file endp
;-----------------------------------
Open_file proc name_
invoke CreateFileA,name_,GENERIC_READ or GENERIC_WRITE,FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0 
ret
Open_file endp
;-----------------------------------
;eax-buf ;ecx-size
ReadFile2Mem proc file_patch
local buffer:dword
local hFile:dword
local file_size:dword
local ww:dword

invoke Open_file,file_patch 
	cmp eax,-1
	je err
mov hFile,eax
invoke GetFileSize,hFile,0
mov file_size,eax
add eax,4
invoke LocalAlloc, LMEM_FIXED,eax ;создаём буфер
mov buffer,eax
invoke ReadFile,hFile,buffer,file_size,addr ww,0 ;читаем
mov ebx,eax
invoke CloseHandle,hFile
	cmp ebx,0
	je err
mov eax,buffer
add eax,file_size
mov dword ptr [eax],0
mov ecx,file_size
mov eax,buffer
ret
	err:
	mov eax,0
	ret
ReadFile2Mem endp
;-----------------------------------
WriteMem2File proc file_patch,src,num
local hFile:dword
local ww:dword
invoke Create_file,file_patch
	cmp eax,-1
	je err
mov hFile,eax
invoke WriteFile,hFile,src,num,addr ww,0
	cmp eax,0
	je err
invoke CloseHandle,hFile
mov eax,0
ret
	err:
	invoke CloseHandle,hFile
	mov eax,-1
	ret
WriteMem2File endp
;-----------------------------------
CopyBinZ proc src,dest,num
pushad
mov esi,src
mov edi,dest
mov ecx,num
rep movsb
add edi,ecx
mov byte ptr [edi],0
popad
ret
CopyBinZ endp
;-----------------------------------
CopyBin proc src:dword,dest:dword,num:dword
pushad
mov esi,src
mov edi,dest
mov ecx,num
rep movsb
popad
ret
CopyBin endp
;-----------------------------------
;замена бинарных строк
ReplaceBin proc message,message_len,sub_string,sub_string_len,rep_message,rep_massage_len,dest_message
local dest_message_orig
m2m dest_message_orig,dest_message
cmp message_len,0
je @err
mov esi,0
mov edi,message
;ищем подстроку
@@:
invoke BinSearch,esi,message,message_len,sub_string,sub_string_len
.if eax!=-1 && eax!=-2 && eax!=-3
;нашли, копируем всё ДО неё
mov edi,esi
mov esi,eax
mov ecx,esi
sub ecx,edi ; длина блока
add edi,message ; начало блока
invoke CopyBin,edi,dest_message,ecx
add dest_message,ecx
invoke CopyBin,rep_message,dest_message,rep_massage_len
mov eax,rep_massage_len
add dest_message,eax
mov eax,sub_string_len
add esi,eax
jmp @B
.elseif
;копируем до конца
mov eax,message_len
sub eax,esi
;sub eax,sub_string_len
mov edi,message
add edi,esi
invoke CopyBin,edi,dest_message,eax
add eax,dest_message
sub eax,dest_message_orig
;eax - длина после замены
.endif
ret
@err:
mov eax,-1
ret
ReplaceBin endp
;-------------------------------