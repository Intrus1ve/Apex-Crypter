#pragma once
#include "common.h"

#define MIN_SIZE_DECRYPT 0x180//0xC0
bool infect(BLOCK bf,BLOCK drop,BLOCK *out);
bool mem_valid(BLOCK *b,uint8* p,uint32 align);
uint32 rnd();
uint32 rnd(uint32 a);

#pragma pack(push,1)
struct ITEM_CALL{
	uint32 offset;
	uint32 rva;
	uint32 offset_in;
	uint32 rva_in;
	uint32 len_func;
};

struct LIST_CALL{
	uint32 count;
	ITEM_CALL *list;
};

struct BLOCK_FILE{
	uint32 size;
	uint8 *data;
	uint32 offset;
	uint32 rva;
};

struct IMPORT_TABLE{
    uint32 OriginalFirstThunk;
    uint32 TimeDateStamp;
    uint32 ForwarderChain;
    uint32 Name;
    uint32 FirstThunk;
};

#pragma pack(pop)