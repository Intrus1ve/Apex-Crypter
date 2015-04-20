
.data
final_entropy qword 0
fpus dq 0
byte_mass dd 256d dup (0)

.code
fpu_init_var proc 
mov dword ptr [final_entropy],0
mov dword ptr [final_entropy+4],0
mov dword ptr [fpus],0
mov dword ptr [fpus+4],0
ret
fpu_init_var endp

fpu_load_dec proc addr_of_byte:dword
local string_dd [16]:byte
invoke dwtoa,addr_of_byte,addr string_dd 
invoke FpuAtoFL, ADDR string_dd, 0, DEST_FPU
ret
fpu_load_dec endp

enropy_of_st proc 
local string_dd [8]:byte
FYL2X 
;сохраняем значение
fld qword ptr [final_entropy]
fadd
fstp qword ptr [final_entropy]
ret
enropy_of_st endp


fpu_div_dec proc uses ecx dec_1:dword,dec_2:dword
;st(0) - результат деления
local some:qword
invoke fpu_load_dec,dec_1
invoke fpu_load_dec,dec_2
fdiv st(1),st(0)
fstp qword ptr [some] 
ret
fpu_div_dec endp

;----------------------------------------------
free_all_byte_mass proc uses ecx eax 
lea eax,byte_mass
mov ecx,256d
@@:
mov dword ptr [eax],0
add eax,4d
loop @B
ret
free_all_byte_mass endp

free_byte_mass proc uses ebx eax  byte_num:dword
mov eax,byte_num
mov ebx,4
mul ebx
add eax,offset byte_mass
mov dword ptr [eax],0
ret
free_byte_mass endp

inc_byte_mass proc uses eax ebx byte_num:dword
mov eax,byte_num
mov ebx,4
mul ebx
add eax,offset byte_mass
inc dword ptr [eax]
ret
inc_byte_mass endp

get_byte_mass proc uses ebx byte_num:dword
mov eax,byte_num
mov ebx,4
mul ebx
add eax,offset byte_mass
mov eax, dword ptr [eax]
ret
get_byte_mass endp

;eax - целая часть. edx - дробная.
parse_float proc string
local unit,float
pushad
mov eax,string
.while byte ptr [eax]!='.' && byte ptr [eax]!=0
inc eax
.endw
.if byte ptr [eax]!=0
mov byte ptr [eax],0
inc eax
invoke atodw,eax
mov float,eax
invoke atodw,string
mov unit,eax
.elseif
popad
mov eax,-1
.endif
popad
mov eax,unit
mov edx,float
ret
parse_float endp
;----------------------------------------------

get_message_entropy  proc uses ebx ecx esi mess:dword,mess_len:dword,in_string:dword
LOCAL content[108] :BYTE
FSAVE content
invoke fpu_init_var
invoke free_all_byte_mass
mov eax,mess
mov ecx,mess_len
dec eax
mov ebx,0
@@:
mov bl,byte ptr [eax+ecx]
invoke inc_byte_mass,ebx
loop @B

mov esi,mess
mov ecx,mess_len
dec esi
mov ebx,0
@@:
mov bl,byte ptr [esi+ecx]
invoke get_byte_mass,ebx
.if eax!=0
	invoke free_byte_mass,ebx
	invoke fpu_div_dec,eax,mess_len
	fld st(0)
	invoke enropy_of_st
.endif
loop @B
fld qword ptr [final_entropy]
fchs ;[-]->[+]
invoke FpuFLtoA, 0, 4, ADDR fpus, SRC1_FPU or SRC2_DIMM
invoke szTrim,addr fpus
.if in_string==0
	;eax - целая часть. edx - дробная.
	invoke parse_float,addr fpus
.elseif
	lea eax,fpus
.endif
FRSTOR content
ret
get_message_entropy endp
;----------------------------------------------


;invoke get_message_entropy,addr ClMessage,lMesLen 

