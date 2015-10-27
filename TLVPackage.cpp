#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typeinfo>
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
const uint8_t* TLVPackage::GetTlvHeader(const uint8_t* buffer, uint32_t length, Tlv_t *tlv)
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

// allocate and copy value data from a buffer into a TLV
// the allocated memory will free when TLV destruct
int TLVPackage::CopyBuff2TlvValue(const uint8_t *buffer,Tlv_t *tlv)
{
	if(tlv->length + 3 > tlv->buff_length) {
		int i = 2;
		while(i * BUFF_INCREMENT_SIZE < tlv->length + 3)i++;
		uint8_t *ptr;
		ptr = (uint8_t*)realloc(tlv->value, i * BUFF_INCREMENT_SIZE);
		//allocte memory fail
		if(ptr == NULL)
			return -1;
		tlv->value = ptr;
		tlv->buff_length = i * BUFF_INCREMENT_SIZE;
	}
	memcpy(tlv->value, buffer, tlv->length);
	return 0;
}


int TLVPackage::Construct(const uint8_t *buffer, uint32_t bufferLength,
		TLVEntity *tlvs,uint32_t &entitySize)
{
	const uint8_t *p;
	if((p = GetTlvHeader(buffer, bufferLength, tlvs)) == NULL) {
		//paese head error
		return -1;
	}
	if(CopyBuff2TlvValue(p, tlvs)) {
		// Coyp data error
		return -1;
	}
	entitySize++;

	// there are remain buffer data,i assume it as another tlv
	if(buffer + bufferLength > p + tlvs->length) {
		if(entitySize >= MAX_TLVOBJ_SIZE) {
			//too many tlvobj in this buffer
			return -1;
		}
		// it's strange that i pass 'p + tlvs->length' to this func,it will be get a wrong position,
		// it just point to the next two bytes enven if 'p + tlvs->length' point to right position.
		const uint8_t *newbuff = p + tlvs->length;
		if(Construct(newbuff, (buffer + bufferLength) - newbuff, ++tlvs, entitySize))
			return -1;
	}
	return 0;
}

uint8_t* TLVPackage::CopyTlvValue2Buff(const TLVEntity *tlv,uint8_t *buffer)
{
	memcpy(buffer, tlv->value, tlv->length);
	// reutrn the next byte in buffer
	return buffer + tlv->length;
}

int TLVPackage::Parse(const TLVEntity *tlvs, uint32_t entitySize,
		uint8_t *buffer, uint32_t &bufferLength)
{
	if(entitySize > 0) {
		if(tlvs->tag <= 0xff) {
			// one byte tag
			buffer[bufferLength++] = (tlvs->tag & 0xff);
		}
		else {
			// two bytes tag
			buffer[bufferLength++] = ((tlvs->tag >> 8) & 0xff);
			buffer[bufferLength++] = (tlvs->tag & 0xff);
		}

		uint8_t *ptr;
		ptr = SetLength(tlvs->length, buffer + bufferLength);
		ptr = CopyTlvValue2Buff(tlvs, ptr);
		bufferLength = ptr - buffer;
		return Parse(++tlvs, --entitySize, buffer, bufferLength);
	}
	return 0;
}

uint8_t TLVPackage::GetTlvHeaderSize(const Tlv_t *tlv)
{
	uint8_t tag_len = tlv->tag <= 0xff ? 1 : 2;

	uint8_t val_len_len = 1;
	if(tlv->length > 0x7f) {
		uint8_t c = 0;
		uint32_t v = tlv->length;
		while(v != 0) {
			v >>= 8;
			c++;
		}
		val_len_len += c;
	}
	return tag_len + val_len_len;
}

// add a child TLV object into a TLV container
// I assume this means to copy a TLV object within the data field
int TLVPackage::AddTlv(Tlv_t *tlv,Tlv_t *child_tlv)
{
	if(tlv->length + child_tlv->length + 6 > tlv->buff_length) {
		int i = 2;
		while(i * BUFF_INCREMENT_SIZE < tlv->length + child_tlv->length + 6)i++;
		uint8_t *ptr;
		ptr = (uint8_t*)realloc(tlv->value, i * BUFF_INCREMENT_SIZE);
		//allocate memory failed
		if(ptr == NULL)
			return -1;
		tlv->value = ptr;
		tlv->buff_length = i * BUFF_INCREMENT_SIZE;
	}
	uint32_t buflen = 0;
	if(Parse(child_tlv, 1, tlv->value + tlv->length, buflen))
		return -1;
	tlv->length += buflen;
	return 0;
}

template<class T> void TLVPackage::BasicValSet(Tlv_t *tlv, T par)
{
	tlv->length = sizeof(T);
	memcpy(tlv->value, &par, sizeof(T));
	if(typeid(T) == typeid(bool))
		tlv->tag = 1;
	if(typeid(T) == typeid(int8_t))
		tlv->tag = 2;
	if(typeid(T) ==  typeid(uint8_t))
		tlv->tag = 3;
	if(typeid(T) == typeid(int16_t))
		tlv->tag = 4;
	if(typeid(T) == typeid(uint16_t))
		tlv->tag = 5;
	if(typeid(T) ==  typeid(int32_t))
		tlv->tag = 6;
	if(typeid(T) == typeid(uint32_t))
		tlv->tag = 7;
	if(typeid(T) == typeid(int64_t))
		tlv->tag = 8;
	if(typeid(T) == typeid(uint64_t))
		tlv->tag = 9;
	if(typeid(T) == typeid(float))
		tlv->tag = 10;
	if(typeid(T) == typeid(double))
		tlv->tag = 11;
	if(typeid(T) == typeid(char))
		tlv->tag = 12;
	if(typeid(T) == typeid(NULL))
		tlv->tag = 15;

}

void TLVPackage::Tlv_Debug(Tlv_t* tlv, int tlv_size)
{
	while(tlv_size--) {
		int i, j, k;
		char ascii_buf[8+1];

		printf("> tlv tag: %x\n", tlv->tag);
		printf("> tlv len: %d\n", tlv->length);
		printf("> tlv data:\n");
		for (i=0, j=0, k=0; i<tlv->length; i++) {
			printf("%02x ", (uint8_t)tlv->value[i]);
			ascii_buf[k++] = ((tlv->value[i] >= 0x20) && (tlv->value[i] < 0x7f)) ? tlv->value[i] : '.';
			if (++j%8 == 0) {
				ascii_buf[k] = '\0';
				printf("\t%s\n", ascii_buf);
				k = 0;
			}
		}
		if (j%8 != 0) {
			ascii_buf[k] = '\0';
			for (i=k; i<8; i++) printf("   ");
			printf("\t%s\n", ascii_buf);
			k = 0;
		}
		printf("\n");
		tlv++;
	}
}

