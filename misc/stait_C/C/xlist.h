/***************************************************************************************************************\
*																												*
*							МОДУЛЬ ДЛЯ РАБОТЫ СО ОДНОНАПРАВЛЕННЫМ СВЯЗНЫМ СПИСКОМ								*
*												(ОБЪЯВЛЕНИЯ)													*
*																												*
*		Список используется для хранения/сортировки/etc данных, взятых с таблиц импорта разных PE-файлов		*
*																												*
*	InitList, ShowListAll, DestroyListAll, AddElemDll, AddElemFunc, GetInfoAll, FindElem, SwapElem, BubbleSort	*
*																												*
\***************************************************************************************************************/



#pragma once	//подключаем файл только один раз (если компилер выпендривается, тогда коментим эту строку, и вместо нее прописываем include-guard (блядь, дефайны по-русски));  



#include <windows.h>
#include <stdio.h>
#include <conio.h> 



#define FindElemDll				FindElem<list_dll_node, list_dll>
#define FindElemFunc			FindElem<list_func_node, list_dll_node>
#define BubbleSortDll			BubbleSort<list_dll, list_dll_node>
#define BubbleSortFunc			BubbleSort<list_dll_node, list_func_node>

#define	MAX_PER	100.0



//структура для сбора данных из списка;
typedef struct get_info_from_list
{
	int num_dll;		//сумма всех уникальных длл (то есть сумма всех длл без повторений);
	int num_func;		//сумма всех уникальных функций во всех длл(сумма всех list_dll_node.num_func); 
	int num_all_dll;	//сумма всех длл, включая повторения (сумма всех list_dll_node.count);
	int num_all_func;	//сумма всех функций, включая повторения, во всех длл (сумма всех list_dll_node.num_all_func); 
}GIFL;

 
//структура для хранения данных функции; 
typedef struct list_func_node
{
	char *pName;			//имя очередной функции;
	int count;				//кол-во повторений функции;
	list_func_node *pNext;	//указатель на следующий элемент списка (на следующие данные другой функи); 
}LFN;


//структура для хранения данных длл и данных функций, принадлежащих (импортируемых) данной длл;
typedef struct list_dll_node
{
	char *pName;			//имя dll; 
	int count;				//число повторений данной dll; 
	int num_func;			//кол-во уникальных (одинарных) функций в данной длл (то есть кол-во функций без повторений в данной длл);
	int num_all_func;		//кол-во всех функций, включая повторения, для данной длл;
	list_func_node *pFirst;	//указатель на начало списка list_func_node (там, где хранятся данные по каждой функе, принадлежащей данной длл);
	list_dll_node *pNext;	//указатель на следующий элемент списка; 
}LDN;


//структура для хранения головы списка list_dll_node;
typedef struct
{
	list_dll_node *pFirst;	//указатель на начало списка list_dll_node;
}list_dll;



void InitList(list_dll *p);
void WriteListAll(list_dll *p, FILE *file, GIFL *pgifl);
void DestroyListAll(list_dll *p);
BOOL AddElemDll(list_dll *p, char *pszDllName); 
BOOL AddElemFunc(list_dll *p, char *pszDllName, char *pszFuncName);
GIFL *GetInfoAll(list_dll *p, GIFL *pgifl); 

template <class A, class B>
A *FindElem(B *p, char *pszName, int *fl);

template <class A, class B>
A *SwapElem(B *p, A *pPrev, A *pCur, A *pNext);

template <class A, class B>
DWORD BubbleSort(A *p); 

DWORD BubbleSortAll(list_dll *p); 



extern list_dll ld;	//(внешняя) глобальная переменная, которую видно для всех файлов программы (со статической продолжительностью существования, во как нахер ); 
 







 








 