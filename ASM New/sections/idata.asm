%include "include/global_constants.inc"
%include "include/section_addresses.inc"

[ORG IDATA_SECTION_ADDRESS]

KERNEL_IMAGE_IMPORT_MODULE_DIRECTORY:
	.RVAFunctionNameList: 		dd KERNEL_IMPORT_INFORMATION.FUNCTION_NAME_LIST
	.Reserved1: 				dd 0
	.Reserved2:	 				dd 0
	.RVAModuleName:	 			dd KERNEL_IMPORT_INFORMATION.MODULE_NAME
	.RVAFunctionAddressList: 	dd KERNEL_IMPORT_INFORMATION.FUNCTION_ADDRESS_LIST

DUMMY_IMAGE_IMPORT_MODULE_DIRECTORY:
	.RVAFunctionNameList: 		dd 0
	.Reserved1: 				dd 0
	.Reserved2:	 				dd 0
	.RVAModuleName:	 			dd 0
	.RVAFunctionAddressList: 	dd 0

KERNEL_IMPORT_INFORMATION:
	.MODULE_NAME:
		db "Kernel32.dll", 0

	.strBeep: 			db 0, 0, "Beep", 0
	.strCreateFileA: 	db 0, 0, "CreateFileA", 0

	.FUNCTION_NAME_LIST:
		dd .strBeep
		dd .strCreateFileA
		dd 0

	.FUNCTION_ADDRESS_LIST:
		dd .Beep
		dd .CreateFileA
	
	.FUNCTION_ADDRESSES:
		.Beep: 		  dd 0
		.CreateFileA: dd 0