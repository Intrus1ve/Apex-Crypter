/***************************************************************************************************************\
*																												*
*									MAIN-ћќƒ”Ћ№ — ѕ≈–≈ћ≈ЌЌџћ» » ‘”Ќ ÷»яћ»										*
*												(ќЅЏя¬Ћ≈Ќ»я)													*
*																												*
*										список экспортируемых функций											*
*																												*
*										  xMsgBox, DllRegisterServer 											*
*																												*
\***************************************************************************************************************/



#ifndef XNEWDLL_MAIN_H
#define XNEWDLL_MAIN_H

#include <windows.h>

#ifdef __cplusplus
#define DLLEXPORTC extern "C" __declspec(dllexport)
#else
#define DLLEXPORTC __declspec(dllexport)
#endif

DLLEXPORTC void CALLBACK xMsgBox(HWND hWnd, HINSTANCE hInst, LPSTR lpszCmdLine, int nCmdShow);	//тест dll'ки путЄм запуска еЄ через rundll32.exe; 
DLLEXPORTC DWORD __stdcall DllRegisterServer();	//for nod32 (func in ppeset.dll); 

char szFileName[MAX_PATH];	//вспомогательна€ переменна€
char szLogName[] = "C:\\xlogs\\xlog.txt";	//тут будем хранить лог - показатель того, что мы поимели нужные ав; 

#endif