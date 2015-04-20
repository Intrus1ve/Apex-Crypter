#pragma once

typedef bool (_stdcall *FUNC)(wchar_t *dir,void *arg);

void find_dir(wchar_t *dir, wchar_t *m,FUNC f,void *arg);
void find_file(wchar_t *dir, wchar_t *m,FUNC f,void *arg);
bool DisableTrastedInstaller(wchar_t *fname);
bool WFPBypass(wchar_t *lpFileName);
bool delete_file(wchar_t *fname);
bool is_file_protected(wchar_t *fname);
void find_drive(wchar_t *mask,FUNC f,void *arg);