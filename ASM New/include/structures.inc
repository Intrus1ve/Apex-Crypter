STRUC DOS_HEADER
    .e_magic:       resw 1
    .e_cblp:        resw 1
    .e_cp:          resw 1
    .e_crlc:        resw 1
    .e_cparhdr:     resw 1
    .e_minalloc:    resw 1
    .e_maxalloc:    resw 1
    .e_ss:          resw 1
    .e_sp:          resw 1
    .e_csum:        resw 1
    .e_ip:          resw 1
    .e_cs:          resw 1
    .e_lsarlc:      resw 1
    .e_ovno:        resw 1
    .e_res:         resw 4
    .e_oemid:       resw 1
    .e_oeminfo:     resw 1
    .e_res2:        resw 10
    .e_lfanew:      resd 1
ENDSTRUC

STRUC LDR_MODULE
	.InLoadOrder 	resd 2
	.InMemOrder 	resd 2
	.InInitOrder	resd 2
	.DllBase		resd 1
	.EntryPoint 	resd 1
	.Reserved		resd 1
	.FullDllName	resd 2
	.BaseDllname	resd 2
ENDSTRUC

STRUC NT_HEADER
	.Signature		resd 1
	.FileHeader		resd 5
	.OptionalHeader	resb 0
ENDSTRUC

STRUC OPTIONAL_HEADER
	.Magic 							resw 1
	.MajorLinkerVersion				resb 1
	.MinorLinkerVersion				resb 1
	.SizeOfCode						resd 1
	.SizeOfInitializedData 			resd 1
	.SizeOfUninitializedData 		resd 1
	.AddressOfEntryPoint 			resd 1
	.BaseOfCode 					resd 1
	.BaseOfData 					resd 1
	.ImageBase 						resd 1
	.SectionAlignment 				resd 1
	.FileAlignment 					resd 1
	.MajorOperatingSystemVersion	resw 1
	.MinorOperatingSystemVersion	resw 1
	.MajorImageVersion	 			resw 1
	.MinorImageVersion	 			resw 1
	.MajorSubsystemVersion	 		resw 1
	.MinorSubsystemVersion	 		resw 1
	.Win32VersionValue	 			resd 1
	.SizeOfImage		 			resd 1
	.SizeOfHeaders		 			resd 1
	.CheckSum			 			resd 1
	.Subsystem	 					resw 1
	.DllCharacteristics	 			resw 1
	.SizeOfStackReserve	 			resd 1
	.SizeOfStackCommit	 			resd 1
	.SizeOfHeapReserve	 			resd 1
	.SizeOfHeapCommit 				resd 1
	.LoaderFlags 					resd 1
	.NumberOfRvaAndSizes 			resd 1
	.DataDirectories:
ENDSTRUC

STRUC FunctionEntry
	.AddressOfName 		resd 1
	.AddressOfPointer 	resd 1
ENDSTRUC