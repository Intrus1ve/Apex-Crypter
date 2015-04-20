#ifndef SOURCE_H
#define SOURCE_H

#include <stdio.h>
#include <time.h>
#include <Windows.h>

LONG __stdcall VEH_RESTORE_ESP(_In_  PEXCEPTION_POINTERS ExceptionInfo);
void select_function_and_complete_routine(LPVOID hKernel32, PIMAGE_EXPORT_DIRECTORY pIED);
int BlackBoxRoutine();

#endif