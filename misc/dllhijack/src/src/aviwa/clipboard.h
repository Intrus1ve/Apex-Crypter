/***************************************************************************************************************\
*																												*
*									МОДУЛЬ ДЛЯ РАБОТЫ С БУФЕРОМ ОБМЕНА (БО)										*
*												(ОБЪЯВЛЕНИЯ)													*
*																												*
*					копирование (списка имён файлов) данных в БО, получение данных из БО, 						*
*					определение типа операции с данными в БО, помещение данных из БО на диск					*
*																												*
*			CopyPasteFileToClipboard, GetDataFromClipboard, ClipboardOperationType, CopyPasteFileToDisk			*
*																												*
\***************************************************************************************************************/



#pragma once

#include <windows.h>
#include <shlobj.h>



BOOL CopyPasteFileToClipboard(HWND hWnd, char *pszFileName, DWORD de_action);
char **GetDataFromClipboard(HWND hWnd);
int ClipboardOperationType(HWND hWnd);
int CopyPasteFileToDisk(char *pszFrom, char *pszTo, DWORD op_type);
