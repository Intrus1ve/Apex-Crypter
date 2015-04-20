;[BITS 32]
[ORG 0x1000]

;	.text section structure
;	
;	-> random functions
;	-> EntryPoint (AddressOfEntryPoint)
;	-> random functions
;	-> tls
;	-> random functions
;	-> could be payload depends on setup

Pre_EP_Functions:
	;[PRE_EP_FUNCTIONS]

EP_FUNC:
	;[EP_FUNCTION]

TLS_CALLBACK:
	%include "include/tls_callback.inc"

Post_EP_Functions:
	;[POST_EP_FUNCTIONS]

	;incbin "include/payload.bin"