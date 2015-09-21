#include <cstdio>
#include "TLVPackage.h"


uint32_t TLVPackage::GetLength(const uint8_t *data)
{
	uint8_t len_bytes = *data;
	if(!(len_bytes & FOLLOWS_LEN_BYTE_MASK)) 
		return len_bytes;

	uint32_t len = 0;
	len_bytes &= 0x7f;
	for(uint32_t i = 1; i<=len_bytes; i++) 
		len = (len << 8) | data[i];
	return len;
}

uint8_t* TLVPackage::SetLength(uint32_t len, uint8_t *buffer)
{
	uint8_t *p = buffer;
	if(len <= 0x7f) {
		// 1 byte len
		*p++ = (len & 0xff);
	}
	else {
		// multi-byte len
		if(len <= 0xff) {
			*p++ = 0x81;
			*p++ = (len & 0xff);
		}
		else if(len <= 0xffff) {
			*p++ = 0x82;
			*p++ = (len >> 8) & 0xff;
			*p++ = len & 0xff;
		}
		else if(len <= 0xffffff) {
			*p++ = 0x83;
			*p++ = (len >> 16) & 0xff;
			*p++ = (len >> 8) & 0xff;
			*p++ = len & 0xff;
		}
		else {
			*p++ = 0x84;
			*p++ = (len >> 24) & 0xff;
			*p++ = (len >> 16) & 0xff;
			*p++ = (len >> 6) & 0xff;
			*p++ = len & 0xff;
		}
	}
	// pointer to next available byte in buffer
	return p;
}

/* only parse the first tlvobj in buffer */
const uint8_t* TLVPackage::ParseTlvHeader(const uint8_t* buffer, uint32_t length, Tlv_t *tlv)
{
	uint32_t i, j;
	uint8_t b;
	uint8_t len_bytes;
	uint8_t state = 0;

	for (i=0; i<length; i++) {
		// read next byte and process it with state machine
		b = buffer[i];

		switch (state) {
			case 0:
				// looking for tag byte #1
				if ((b & SINGLE_TAG_BYTE_MASK) < SINGLE_TAG_BYTE_MASK) {
					tlv->tag = b;
					state = 2;
				} else if ((b & SINGLE_TAG_BYTE_MASK) == SINGLE_TAG_BYTE_MASK) {
					tlv->tag = b;
					state = 1;
				}
				break;
			case 1:
				// looking for tag byte #2
				tlv->tag = (tlv->tag << 8) | b;
				state = 2;
				break;
			case 2:
				// looking for length byte 1
				if (!(b & FOLLOWS_LEN_BYTE_MASK)) {
					tlv->length = b;
					state = 4;
				} else {
					// set up counters for variable-length length field
					j = 0;
					len_bytes = (b & 0x7F);
					// the length can only allocate 4 bytes
					if(len_bytes > 4)
						return NULL;
					state = 3;
				}
				break;
			case 3:
				// looking for more length bytes
				tlv->length = (tlv->length << 8) | b;
				if (++j == len_bytes) {
					state = 4;
				}
				break;
			case 4:
				if (length-i < tlv->length) {
					// buffer doesn't have enough data left? give up!
					return NULL;
				} else {
					return &buffer[i];
				}
		}
	}
	return NULL;
}

int TLVPackage::Construct(const uint8_t *buffer, uint32_t bufferLength,
		TLVEntity *tlvEntity,uint32_t &entityLength)
{

}
