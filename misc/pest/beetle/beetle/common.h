#pragma once

typedef unsigned char	uint8;
typedef unsigned short	uint16;
typedef unsigned int	uint32;

#pragma pack(push,1)
struct BLOCK{
	uint32	size;
	uint8*	data;
};
#pragma pack(pop)

#if _DEBUG
	void m_wprintf(wchar_t *frm,...);
	bool append_file(wchar_t *fname,wchar_t *s);
#endif
void *m_malloc(int size);
void m_free(void *p);
void *m_realloc(void *p,int size);
bool load_file(wchar_t *fname,BLOCK *b);
bool save_file(wchar_t *fname,BLOCK *b);