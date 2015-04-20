#include "Source.h"

DWORD rng_in_range(DWORD min, DWORD max)
{
	return min + (rand() % (DWORD)(max - min + 1));
}

typedef struct _BLACKBOX_FUNCTION
{
	LPVOID FunctionAddress;
	CHAR* FunctionName;
} BLACKBOX_FUNCTION, *PBLACKBOX_FUNCTION;

DWORD NEW_ESP;
DWORD OLD_ESP;
DWORD REAL_ESP;

DWORD EAX_FIRST;
DWORD EAX_SECOND;

DWORD EBX_FIRST;
DWORD EBX_SECOND;

DWORD ECX_FIRST;
DWORD ECX_SECOND;

DWORD EDX_FIRST;
DWORD EDX_SECOND;

LPVOID GLBL_HK32;
PIMAGE_EXPORT_DIRECTORY GLBL_PIED;

LONG __stdcall VEH_RESTORE_ESP(_In_  PEXCEPTION_POINTERS ExceptionInfo)
{
	__asm { mov esp, REAL_ESP }

	return ExceptionContinueExecution;

}

LONG __stdcall VEH_CONTINUE(_In_  PEXCEPTION_POINTERS ExceptionInfo)
{
	return 0;
}

void select_function_and_complete_routine(LPVOID hKernel32, PIMAGE_EXPORT_DIRECTORY pIED)
{
__SELECT_FUNCTION:

	DWORD dwIndexOfRandomFunc = rng_in_range(0, pIED->NumberOfNames); // no ordinals

	printf("[+] Random Index of Function Chosen: %d\n", dwIndexOfRandomFunc);

	DWORD* lpAddressOfNames = (DWORD*)((DWORD)hKernel32 + pIED->AddressOfNames);
	DWORD* lpAddressOfFunctions = (DWORD*)((DWORD)hKernel32 + pIED->AddressOfFunctions);
	DWORD* lpAddressOfNameOrdinals = (DWORD*)((DWORD)hKernel32 + pIED->AddressOfNameOrdinals);

	printf("[+] Address of Exported Functions: 0x%008X\n", lpAddressOfNames);

	PBLACKBOX_FUNCTION BBFunction = new BLACKBOX_FUNCTION();

	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		if (dwIndexOfRandomFunc == i)
		{
			BBFunction->FunctionName = (CHAR*)((DWORD)hKernel32 + lpAddressOfNames[i]);
			BBFunction->FunctionAddress = GetProcAddress((HMODULE)hKernel32, BBFunction->FunctionName); // didn't feel like supporting forwarded functions
		}
	}

	printf("[+] Function->Address: 0x%008X\n", BBFunction->FunctionAddress);
	printf("[+] Function->Name: %s\n", BBFunction->FunctionName);

	LPVOID pFuncAddress = BBFunction->FunctionAddress;

	// *****************************************************
	// *****************************************************
	// *************** EXECUTE PARAM RUN *******************
	// *****************************************************
	// *****************************************************

	AddVectoredExceptionHandler(1, VEH_RESTORE_ESP);

	__try
	{
		__asm
		{
			mov REAL_ESP, esp;

			push 0
				push 0
				push 0
				push 0

				push 0
				push 0
				push 0
				push 0

				push 0
				push 0
				push 0
				push 0

				push 0
				push 0
				push 0
				push 0

				mov OLD_ESP, esp

				mov eax, pFuncAddress
				call eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	__asm
	{
		mov NEW_ESP, esp
			mov esp, REAL_ESP
	}

	printf("[+] Old ESP: %d\n", OLD_ESP);
	printf("[+] New ESP: %d\n", NEW_ESP);

	DWORD dwNumberOfArgs = (NEW_ESP - OLD_ESP) / 4;
	printf("[+] BlackBox Function Arguments: %d\n", dwNumberOfArgs);

	RemoveVectoredExceptionHandler(VEH_RESTORE_ESP);


	// *****************************************************
	// *****************************************************
	// *************** EXECUTE FIRST RUN *******************
	// *****************************************************
	// *****************************************************

	DWORD dwRandParam = rng_in_range(0x00, 0xFFFF);

	AddVectoredExceptionHandler(1, VEH_RESTORE_ESP);

	printf("[+] Calling BlackBox Function [1]: %s\n", BBFunction->FunctionName);
	printf("[+] BlackBox Function Param [1]: 0x%008X\n", dwRandParam);

	__try
	{
		__asm
		{
			mov REAL_ESP, esp;
		}

		/* push correct number of args*/
		for (int i = 0; i < dwNumberOfArgs; i++)
			__asm { push dwRandParam }

		__asm
		{
			mov OLD_ESP, esp
				mov eax, pFuncAddress
				call eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//printf("[-] Warning: Bad Function, Selecting New Function...\n");
		//select_function_and_complete_routine(GLBL_HK32, GLBL_PIED);
	}

	__asm
	{ /* Restore ESP */
		mov NEW_ESP, esp
			mov esp, REAL_ESP
	}

	__asm
	{ /* Save anamoly registers */
		mov EAX_FIRST, eax
			mov EBX_FIRST, ebx
			mov ECX_FIRST, ecx
			mov EDX_FIRST, edx
	}

	printf("[+] EAX VALUE [1]: 0x%008X\n", EAX_FIRST);
	printf("[+] EBX VALUE [1]: 0x%008X\n", EBX_FIRST);
	printf("[+] ECX VALUE [1]: 0x%008X\n", ECX_FIRST);
	printf("[+] EDX VALUE [1]: 0x%008X\n", EDX_FIRST);

	RemoveVectoredExceptionHandler(VEH_RESTORE_ESP);

	// *****************************************************
	// *****************************************************
	// *************** EXECUTE SECOND RUN ******************
	// *****************************************************
	// *****************************************************

	DWORD dwRandParam2 = rng_in_range(0x00, 0xFFFF);

	AddVectoredExceptionHandler(1, VEH_RESTORE_ESP);

	printf("[+] Calling BlackBox Function [2]: %s\n", BBFunction->FunctionName);
	printf("[+] BlackBox Function Param [2]: 0x%008X\n", dwRandParam2);

	__try
	{
		__asm
		{
			mov REAL_ESP, esp;
		}

		/* push correct number of args*/
		for (int i = 0; i < dwNumberOfArgs; i++)
			__asm { push dwRandParam2 }

		__asm
		{
			mov OLD_ESP, esp
				mov eax, pFuncAddress
				call eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// printf("[-] Warning: Bad Function, Selecting New Function...\n");
		// select_function_and_complete_routine(GLBL_HK32, GLBL_PIED);
	}

	__asm
	{ /* Restore ESP */
		mov NEW_ESP, esp
			mov esp, REAL_ESP
	}

	__asm
	{ /* Save anamoly registers */
		mov EAX_SECOND, eax
			mov EBX_SECOND, ebx
			mov ECX_SECOND, ecx
			mov EDX_SECOND, edx
	}

	printf("[+] EAX VALUE [2]: 0x%008X\n", EAX_SECOND);
	printf("[+] EBX VALUE [2]: 0x%008X\n", EBX_SECOND);
	printf("[+] ECX VALUE [2]: 0x%008X\n", ECX_SECOND);
	printf("[+] EDX VALUE [2]: 0x%008X\n", EDX_SECOND);

	RemoveVectoredExceptionHandler(VEH_RESTORE_ESP);

	// *****************************************************
	// *****************************************************
	// *************** EXECUTE TESTING RUN *****************
	// *****************************************************
	// *****************************************************

	// FUNCTION: InstallELAMCertificateInfo
	// ECX: 0x7F02D000

	//BOOL B_EAX, B_EBX, B_ECX, B_EDX;

	//if (EAX_FIRST != 0 && EAX_FIRST == EAX_SECOND)
	//	B_EAX = TRUE;
	//if (EBX_FIRST != 0 && EBX_FIRST == EBX_SECOND)
	//	B_EBX = TRUE;
	//if (ECX_FIRST != 0 && ECX_FIRST == ECX_SECOND)
	//	B_ECX == TRUE;
	//if (EDX_FIRST != 0 && EDX_FIRST == EDX_SECOND)
	//	B_EDX = TRUE;

	//DWORD dwRandParam3 = rng_in_range(0x00, 0xFFFF);

	//DWORD F_ECX;
	//DWORD F_EDX;

	//if (B_ECX)
	//{ /* ECX anamoly */

	//	for (int i = 0; i < dwNumberOfArgs; i++)
	//		__asm { push dwRandParam3 }

	//	__asm
	//	{
	//		mov eax, pFuncAddress
	//			call eax
	//			mov F_ECX, ecx
	//	}

	//	if (F_ECX == ECX_FIRST && F_ECX == ECX_SECOND)
	//		printf("[+] ECX ANAMOLY CHECK: TRUE\n");
	//	else
	//		printf("[+] ECX ANAMOLY CHECK: FALSE\n");
	//}

	//if (B_EDX)
	//{ /* EDX anamoly */

	//	for (int i = 0; i < dwNumberOfArgs; i++)
	//		__asm { push dwRandParam3 }

	//	__asm
	//	{
	//		mov eax, pFuncAddress
	//			call eax
	//			mov F_EDX, edx
	//	}

	//	if (F_EDX == EDX_FIRST && F_EDX == EDX_SECOND)
	//		printf("[+] EDX ANAMOLY CHECK: TRUE\n");
	//	else
	//		printf("[+] EDX ANAMOLY CHECK: FALSE\n");
	//}

	printf("\n");
}

int BlackBoxRoutine()
{
	LPVOID hKernel32;

	//__asm
	//{
	//	mov eax, fs:0x30
	//		mov eax, [eax + 0x0C]
	//		mov eax, [eax + 0x14]
	//		mov eax, [eax]
	//		//mov eax, [eax]
	//		mov eax, [eax + 0x10]
	//		mov hKernel32, eax
	//}

	hKernel32 = LoadLibraryA("Kernel32.dll");

	printf("[+] Kernel32 BaseAddress: 0x%008X\n", hKernel32);

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hKernel32;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return -1;

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)pIDH + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
		return -1;

	IMAGE_DATA_DIRECTORY ExportDir = pINH->OptionalHeader.DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hKernel32 + ExportDir.VirtualAddress);

	printf("[+] Kernel32 ExportDirectory Address: 0x%008X\n", pIED);
	printf("[+] Total Exported (By Name) Functions: %d\n", pIED->NumberOfNames);

	GLBL_HK32 = hKernel32;
	GLBL_PIED = pIED;

	select_function_and_complete_routine(hKernel32, pIED);
}


void output_functions_with_no_args(LPSTR szModuleName)
{
	LPVOID hModule = LoadLibraryA(szModuleName);

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)hModule + pIDH->e_lfanew);

	IMAGE_DATA_DIRECTORY dd_Exports = pINH->OptionalHeader.DataDirectory[0];
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + dd_Exports.VirtualAddress);

	DWORD* lpAddressOfNames = (DWORD*)((DWORD)hModule + pIED->AddressOfNames);
	DWORD* lpAddressOfFunctions = (DWORD*)((DWORD)hModule + pIED->AddressOfFunctions);
	DWORD* lpAddressOfNameOrdinals = (DWORD*)((DWORD)hModule + pIED->AddressOfNameOrdinals);

	AddVectoredExceptionHandler(1, VEH_RESTORE_ESP);

	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		CHAR* pszFunctionName = (CHAR*)((DWORD)hModule + lpAddressOfNames[i]);
		LPVOID lpFunctionAddress = GetProcAddress((HMODULE)hModule, pszFunctionName);

		printf("Trying to call function: %s\n", pszFunctionName);

		__try
		{
			__asm
			{
				mov REAL_ESP, esp

					push 0
					push 0
					push 0
					push 0

					push 0
					push 0
					push 0
					push 0

					push 0
					push 0
					push 0
					push 0

					push 0
					push 0
					push 0
					push 0

					mov OLD_ESP, esp

					mov eax, lpFunctionAddress
					call eax
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			continue;
		}
		
		__asm { int 3}


		__asm
		{
			mov NEW_ESP, esp
				mov esp, REAL_ESP
		}

		printf("[+] Old ESP: %d\n", OLD_ESP);
		printf("[+] New ESP: %d\n", NEW_ESP);

		DWORD dwNumberOfArgs = (NEW_ESP - OLD_ESP) / 4;
		printf("[+] Function [%s] \n\tArgument Count: %d\n", pszFunctionName, dwNumberOfArgs);

	}

	RemoveVectoredExceptionHandler(VEH_RESTORE_ESP);

}

int main(void)
{
	// AlpcGetHeaderSize - only 8
	//	Params - 1 arg
	//	ECX will equal your parameter

	//iswalpha --> XP - 8 (XP, VISTA, 8)
	//	Params - 1 arg
	//	ECX = 0x00000103

	//SetConsoleMaximumWindowSize
	// -Params -2
	//[+] ECX VALUE [2]: 0x0041B07D
	//[+] EDX VALUE[2]: 0x002E8014

	// QueueThreadPriority
	//  [+] ECX VALUE[2]:  0xC0000008
	//	[+] EDX VALUE[2] : 0x0000004A

	//HMODULE hNTDLL = LoadLibrary("NTDLL.DLL");
	//LPVOID FUNC = GetProcAddress(hNTDLL, "iswalpha");
	//DWORD lel = 0x87342154;
	//DWORD lel2 = 0x00;


	/*if (ss > 0)
		_asm { int 3}

		__asm{ int 3}*/
	/*__asm
	{
	push lel
	mov eax, FUNC
	call eax
	mov lel2, ecx
	}

	printf("0x%008X\n", lel2);
	system("pause");*/

	srand(time(0) ^ GetProcessId(0));

	BlackBoxRoutine();

	system("pause");

	//output_functions_with_no_args("KERNEL32.DLL");
}