.486
.model flat, stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\wininet.inc
includelib  \masm32\lib\user32.lib
includelib  \masm32\lib\kernel32.lib
include \masm32\include\masm32.inc
includelib  \masm32\lib\masm32.lib
includelib  \masm32\lib\wininet.lib
include \masm32\include\advapi32.inc
includelib \masm32\lib\advapi32.lib
include \masm32\include\wsock32.inc
includelib \masm32\lib\wsock32.lib
include \masm32\macros\macros.asm
include Strings.asm
include \masm32\include\debug.inc
includelib \masm32\lib\debug.lib
include \masm32\include\fpu.inc
includelib  \masm32\lib\fpu.lib
ZeroMemory equ <RtlZeroMemory>
CopyMemory equ <RtlMoveMemory>


.data
OutputFolder  db "temp",0
text_name db '.text',0,0,0
data_name db '.data',0,0,0
code_section_name dd offset text_name
data_section_name dd offset data_name
.data?
hCon dd ?
temp dd ?
;---------------------------------
szString  db 256 dup (?)
szString2  db 256 dup (?)
szString3  db 256 dup (?)
szDataBuffer  db 256 dup (?)

;---------------------------------
size_of_code dd ?
size_of_data dd ?
entropy_of_code dd ?
entropy_of_data dd ?
step_size dd ?
step_number dd ?
;---------------------------------
data_step dd ?
code_step dd ?
code_raw_size dd ?
data_raw_size dd ?
code_raw_entropy db 8 dup (?)
data_raw_entropy db 8 dup (?)
;---------------------------------
hStub dd ?
StubSize dd ?
hStubCopy dd ?
hStubTemp dd ?
StubCopySize dd ?
mem4code dd ?
mem4data dd ?
mem4temp dd ?
hGenFile dd ?
;---------------------------------
.code
include file.asm
include get_entropy.asm
;---------------------------------
size_of_code_cl equ 1
size_of_data_cl equ 2
entropy_of_code_cl equ 3
entropy_of_data_cl equ 4
setion_code_name_cl equ 5
setion_data_name_cl equ 6
;---------------------------------
read_arg proc number,var_addr
local clBuffer[256]:byte
invoke getcl_ex,number,addr clBuffer
;задаётся в хексе
invoke htodw,addr clBuffer 
mov ebx,var_addr
mov dword ptr [ebx],eax
ret
read_arg endp

read_string_arg proc number,var_addr,max_len
local clBuffer[256]:byte
invoke getcl_ex,number,addr clBuffer
invoke szLen,addr clBuffer
.if eax!=0 || eax>max_len
lea ebx,clBuffer
invoke CopyBin,ebx,var_addr,eax
.endif
ret
read_string_arg endp

parse_cl proc arg
invoke read_arg,size_of_code_cl,addr size_of_code
invoke read_arg,size_of_data_cl,addr size_of_data
invoke read_arg,entropy_of_code_cl,addr entropy_of_code
invoke read_arg,entropy_of_data_cl,addr entropy_of_data
invoke read_string_arg,setion_code_name_cl,addr text_name,8
invoke read_string_arg,setion_data_name_cl,addr data_name,8
ret
parse_cl endp

init_rand proc 
mov eax,7ffe0008h ;timer
mov eax,dword ptr [eax]
invoke nseed,eax
ret
init_rand endp

fill_entr proc uses ebx eax ecx data,sized
mov ebx,0
mov eax,data
dec eax
mov ecx,sized
@@:
mov byte ptr [eax+ecx],bl
inc bl
loop @B
ret
fill_entr endp

fill_rand_zero proc dest,sized
;заменяем случайный байт на 0
@@:
invoke nrandom,sized
add eax,dest
mov byte ptr [eax],0
ret
fill_rand_zero endp


replace_rand_zero proc dest,sized
;заменяем случайно выбранный байт во всем сообщении на 0
@@:
invoke nrandom,sized
add eax,dest
mov al,byte ptr [eax]
cmp al,0
je @B
mov ecx,sized
mov edx,dest
@@:
	cmp byte ptr [edx],al
	jne @1
	mov byte ptr [edx],0 
	@1:
	inc edx
loop @B
ret
replace_rand_zero endp



gen_data proc
local hfile:dword
;создаём данные
invoke LocalAlloc,LMEM_FIXED,step_size
mov mem4data,eax
invoke LocalAlloc,LMEM_FIXED,step_size
mov mem4code,eax
invoke LocalAlloc,LMEM_FIXED,step_size
mov mem4temp,eax
;заполняем данными
invoke fill_entr,mem4data,step_size
invoke get_message_entropy,mem4data,step_size,0
;для маленького сообщения энтропия может быть меньше необходимой
.if eax<entropy_of_data
jmp err_size
.endif
invoke fill_entr,mem4code,step_size
invoke get_message_entropy,mem4data,step_size,0
.if eax<entropy_of_code
jmp err_size
.endif
;снижаем энтропию до необходимой
;полученная должна быть чуть-чуть меньше искомой
;так мы исключаем округление в большую сторону

.if entropy_of_code==0
	invoke ZeroMemory,mem4code,step_size
.elseif
	mov eax,9
	.while eax>=entropy_of_code
	;разбавим энтропию, например.
	invoke fill_rand_zero,mem4code,step_size
	invoke get_message_entropy,mem4code,step_size,0
	.endw
.endif

.if entropy_of_data==0
	invoke ZeroMemory,mem4data,step_size
.elseif
	mov eax,9
	.while eax>=entropy_of_data 
	invoke fill_rand_zero,mem4data,step_size
	invoke get_message_entropy,mem4data,step_size,0
	.endw
.endif
;запишем в инклуд
invoke WriteMem2File,$CTA0("data.inc"),mem4data,step_size
invoke WriteMem2File,$CTA0("code.inc"),mem4code,step_size
ret
gen_data endp

;-----------------------------------
;запускает процесс и ждёт завершения
run_wait_process proc ProcName,CLL
local STARTUP_INFO:STARTUPINFO
local p_info:PROCESS_INFORMATION
local szBuff[256]:byte,ModuleName[256]:byte
invoke ZeroMemory,addr STARTUP_INFO,sizeof STARTUPINFO
mov STARTUP_INFO.cb,sizeof STARTUPINFO
invoke NameFromPath,ProcName,addr ModuleName
;парсер командной строки ориентируется по имени модуля
;без кавычек пробел станет разделителем параметров
invoke wsprintf,addr szBuff,$CTA0("%s \=%s\="),addr ModuleName,CLL
invoke CreateProcessA,ProcName,addr szBuff,0,0,0,0,0,0,addr STARTUP_INFO,addr p_info
mov eax,dword ptr [p_info].hProcess
invoke WaitForSingleObject,eax,INFINITE
mov eax,dword ptr [p_info].hProcess
invoke CloseHandle,eax
mov eax,dword ptr [p_info].hThread
invoke CloseHandle,eax
ret
run_wait_process endp
;-----------------------------------
include pe_32.asm



code:
;поехали!
;invoke ClearScreen
invoke StdOut,$CTA0("entropy maker\n")
invoke StdOut,$CTA0("format: [code size] [data size] [code entropy] [data entropy]\noptional: [code name] [data name]\n")

invoke SetConsoleTitle,$CTA0("entropy maker\n")
invoke GetStdHandle,STD_OUTPUT_HANDLE
mov hCon,eax
;прочитаем значения
call parse_cl
invoke init_rand
;проверим валидность данных
.if entropy_of_code>8 || entropy_of_data>8
jmp err_entropy
.endif
.if size_of_code>10000000d || size_of_data >10000000d 
jmp err_size
.endif
;чем меньше размер инклуда, тем быстрее подобрать энтропию
;лучше установить стандартный.
mov step_size,256d ; энтропия 8
mov eax,step_size
.if size_of_code<eax || size_of_data<eax 
jmp err_step_size
.endif
;проверим выходной путь
invoke GetAppPath, addr szDataBuffer
invoke SetCurrentDirectory,addr szDataBuffer
invoke CreateDirectory,addr OutputFolder,0
.if eax==0
invoke GetLastError
cmp eax,ERROR_ALREADY_EXISTS
jne err_bad_output
.endif



read_file:
;прочитаем изначальный файл
invoke ReadFile2Mem,$CTA0("stub.asm")
	cmp eax,0
	je err_file
mov hStub,eax
mov StubSize,ecx
shl ecx,1 ;x2
mov StubCopySize,ecx
invoke LocalAlloc,LMEM_FIXED,StubCopySize
mov hStubCopy,eax
invoke LocalAlloc,LMEM_FIXED,StubCopySize
mov hStubTemp,eax
;формируем инклуды с нужной энтропией
call gen_data


;заменим маркеры инклудов на сами инклуды
invoke CopyBinZ,hStub,hStubCopy,StubSize
;сколько раз инклудим?
mov eax,size_of_data
mov ebx,step_size
mov edx,0
div ebx
invoke dw2a,eax,addr szString2
invoke wsprintf,addr szString,$CTA0("rept %s {file 'data.inc'}"),addr szString2
invoke szLen,addr szString
invoke ReplaceBin,hStubCopy,StubSize,$CTA0("include_data4size"),17,addr szString,eax,hStubTemp
mov StubCopySize,eax
invoke CopyBin,hStubTemp,hStubCopy,StubCopySize

mov eax,size_of_code
mov ebx,step_size
mov edx,0
div ebx
invoke dw2a,eax,addr szString2
invoke wsprintf,addr szString,$CTA0("rept %s {file 'code.inc'}"),addr szString2
invoke szLen,addr szString
invoke ReplaceBin,hStubCopy,StubCopySize,$CTA0("include_code4size"),17,addr szString,eax,hStubTemp
mov StubCopySize,eax
invoke CopyBin,hStubTemp,hStubCopy,StubCopySize


invoke WriteMem2File,$CTA0("stub_geb.asm"),hStubCopy,StubCopySize
;скомпилируем
invoke GetCurrentDirectory,256d,addr szString2
invoke wsprintf,addr szString,$CTA0("%s\\stub_geb.asm"),addr szString2
invoke wsprintf,addr szString3,$CTA0("%s\\fasm\\fasm.exe"),addr szString2
invoke run_wait_process,addr szString3,addr szString
;вычислим реальные значения
invoke ReadFile2Mem,$CTA0("stub_geb.exe")
	cmp eax,0
	je err_file
mov hGenFile,eax
invoke GetSectionByName,hGenFile,code_section_name
	cmp eax,-1
	je err_section_name
invoke GetSection_SizeOfRawData,eax
mov code_raw_size,eax
;энтропия
invoke GetSectionByName,hGenFile,code_section_name
invoke GetSection_PointerToRawData,eax
add eax,hGenFile
invoke get_message_entropy,eax,code_raw_size,1
invoke CopyBin,eax,addr code_raw_entropy,8
;теперь секция данных
invoke GetSectionByName,hGenFile,data_section_name
	cmp eax,-1
	je err_section_name
invoke GetSection_SizeOfRawData,eax
mov data_raw_size,eax
invoke GetSectionByName,hGenFile,data_section_name
invoke GetSection_PointerToRawData,eax
add eax,hGenFile
invoke get_message_entropy,eax,data_raw_size,1
invoke CopyBin,eax,addr data_raw_entropy,8
;---------------------------------
;переименуем
invoke dw2hex,code_raw_size,addr szString3
invoke dw2hex,data_raw_size,addr szString2
invoke wsprintf,addr szString,$CTA0("%s\\code(%s %s)data(%s %s).exe"),addr OutputFolder,addr szString3,addr code_raw_entropy,addr szString2,addr data_raw_entropy
invoke MoveFileA,$CTA0("stub_geb.exe"),addr szString
invoke wsprintf,addr szString,$CTA0("\ncode(%s %s)data(%s %s)\n"),addr szString3,addr code_raw_entropy,addr szString2,addr data_raw_entropy
invoke StdOut,addr szString
;---------------------------------

ok_gen:
invoke StdOut,$CTA0("Compiled: successful\n")
jmp exit_
err_bad_output:
invoke StdOut,$CTA0("Error: bad output folder\n")
err_file:
invoke StdOut,$CTA0("Error: stub-file not found\n")
jmp exit_
err_entropy:
invoke StdOut,$CTA0("Error: bad entropy\n")
jmp exit_
err_size:
invoke StdOut,$CTA0("Error: bad section size\n")
jmp exit_
err_step_size:
invoke StdOut,$CTA0("Error: section size too small\n")
jmp exit_
err_section_name:
invoke StdOut,$CTA0("Error: bad sections name\n")
jmp exit_
exit_:
invoke ExitProcess,0
ret
end code