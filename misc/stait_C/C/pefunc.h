/***************************************************************************************************************\
*																												*
*								МОДУЛЬ ДЛЯ РАБОТЫ С PE32-FILES (IMPORT TABLE)									*
*												(ОБЪЯВЛЕНИЯ)													*
*																												*
*				Проверка файла на соответствие PE, переводы RVA в оффсеты, парсинг импорта etc					*
*																												*
*										ValidPE, RVATpOffset, PrImport											*
*																												*
\***************************************************************************************************************/


 
#pragma once



//#include "xlist.h"	//подключаем модуль для работы со списками (связными);
#include "misc.h"	//прочие вспомогательные функи  



#define RVATOVA(Base, Rva)	((DWORD)Base + (DWORD)Rva)	//дэфайн - получение из RVA -> VA (k.0.) )
#define OFFSTOADDR RVATOVA
#define ALIGN_UP(x, y)	((x + (y - 1)) & (~(y - 1)))	//выравнивание вверх; 
#define ALIGN_DOWN(x, y)	(x & (~(y - 1)))	//вниз; 



BOOL ValidPE(LPVOID pExe);
DWORD RVAToOffset(LPVOID pExe, DWORD Rva);
BOOL WINAPI PrImport(char *pszFileName);
 
 
