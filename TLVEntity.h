#ifndef __TLVENTITY_H__
#define __TLVENTITY_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CONSTRUCT_ENCODED_MASK 0x20
#define SINGLE_TAG_BYTE_MASK 0x1F
#define FOLLOWS_LEN_BYTE_MASK 0x80
#define BUFF_INCREMENT_SIZE 1024

struct TLVEntity {
	uint16_t tag;			//Tag
	uint32_t length;		//Data Length
	uint8_t *value;			//Data
	uint32_t buff_length;		//incase value overfllow

	TLVEntity(){tag = 0;length = 0;buff_length = BUFF_INCREMENT_SIZE;value = (uint8_t*)malloc(BUFF_INCREMENT_SIZE);}
	TLVEntity(uint16_t tag, uint8_t *value, uint32_t value_len)
	{
		this->tag = tag;
		this->value = (uint8_t*)malloc((value_len / BUFF_INCREMENT_SIZE + 1) * BUFF_INCREMENT_SIZE);
		this->length = value_len;
		memcpy(this->value, value, value_len);
		this->buff_length =  (value_len / BUFF_INCREMENT_SIZE + 1) * BUFF_INCREMENT_SIZE;
	}
	virtual ~TLVEntity() {free(value);}
};

typedef struct TLVEntity Tlv_t;

#endif //__TLVENTITY_H__
