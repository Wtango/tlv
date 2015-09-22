#ifndef __TLVENTITY_H__
#define __TLVENTITY_H__

#include <stdint.h>
#include <stdlib.h>

#define CONSTRUCT_ENCODED_MASK 0x20
#define SINGLE_TAG_BYTE_MASK 0x1F
#define FOLLOWS_LEN_BYTE_MASK 0x80

struct TLVEntity {
	uint16_t tag;			//Tag
	uint32_t length;		//Data Length
	uint8_t *value;			//Data

	TLVEntity(){tag = 0;length = 0;value = NULL;}
	virtual ~TLVEntity() {if(this->value != NULL)free(this->value);}
};

typedef struct TLVEntity Tlv_t;

#endif //__TLVENTITY_H__
