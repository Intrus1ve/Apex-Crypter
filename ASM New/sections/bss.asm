;%include "include/section_addresses.inc"
;%include "include/global_constants.inc"
;%include "include/tls_callback_offset.inc"

;[ORG TLS_SECTION_ADDRESS]

;TLS_HEADER:
         
;		 .StartAddressOfRawData: dd 0
 ;        .EndAddressOfRawData:   dd 0
  ;       .AddressOfIndex:        dd IMAGE_BASE + TLS_SECTION_ADDRESS + .Index - TLS_HEADER
   ;      .AddressOfCallBacks:    dd IMAGE_BASE + TLS_SECTION_ADDRESS + .CallbackAddresses - TLS_HEADER
    ;     .SizeOfZeroFill:        dd 0
     ;    .Characteristics:       dd 0

		; .Index:
		;	dd 0

		 ;.CallbackAddresses:
			; dd IMAGE_BASE + TEXT_SECTION_ADDRESS + TLS_CALLBACK_OFFSET
			; dd 0