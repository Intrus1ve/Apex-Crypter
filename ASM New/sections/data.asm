%include "include/global_constants.inc"
%include "include/section_addresses.inc"
%include "include/tls_callback_offset.inc"

[ORG DATA_SECTION_ADDRESS]

DATA:

	.RunPE:
		incbin "obj/runpe.o"
	.RunPELength EQU $ - .RunPE

	.Key:
		%include "include/runpe_key.inc"
	.KeyLength EQU $ - .Key

	.TlsCallback:
		
		.TLS_HEADER:
         
			 .StartAddressOfRawData: dd 0
			 .EndAddressOfRawData:   dd 0
			 .AddressOfIndex:        dd IMAGE_BASE + DATA_SECTION_ADDRESS + .RunPELength + .KeyLength + .Index - .TLS_HEADER
			 .AddressOfCallBacks:    dd IMAGE_BASE + DATA_SECTION_ADDRESS + .RunPELength + .KeyLength + .CallbackAddresses - .TLS_HEADER
			 .SizeOfZeroFill:        dd 0
			 .Characteristics:       dd 0

			 .Index:
				dd 0

			 .CallbackAddresses:
				 dd IMAGE_BASE + TEXT_SECTION_ADDRESS + TLS_CALLBACK_OFFSET
				 dd 0

	.HeurData:
		;[DATA]