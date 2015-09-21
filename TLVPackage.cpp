#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	if(tlv->length != 0)
		tlv->value = (uint8_t*)malloc(sizeof(uint8_t) * tlv->length);
	if(tlv->value == NULL) return -1;
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
		if(entitySize >= MAX_TLVOBJ_ARR) {
			//too many tlvobj in this buffer
			return -1;
		}
		if(Construct(p + tlvs->length, (buffer + bufferLength) - (p + tlvs->length), tlvs++, entitySize))
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

static void PrintBufferHex(const uint8_t* buff, size_t len)
{
	size_t i, j;

	for (i=0, j=0; i<len; i++) {
		printf("%02x ", buff[i]);
		if (++j%8 == 0) printf("\n");
	}
	if (j%8 != 0) printf("\n");
	printf("\n");
}

void Tlv_Debug(Tlv_t* tlv, int tlv_size)
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

uint8_t tlv1Data[] =
{
	0x70,0x43,0x5F,0x20,0x1A,0x56,0x49,0x53,
	0x41,0x20,0x41,0x43,0x51,0x55,0x49,0x52,
	0x45,0x52,0x20,0x54,0x45,0x53,0x54,0x20,
	0x43,0x41,0x52,0x44,0x20,0x32,0x39,0x57,
	0x11,0x47,0x61,0x73,0x90,0x01,0x01,0x00,
	0x10,0xD1,0x01,0x22,0x01,0x11,0x43,0x87,
	0x80,0x89,0x9F,0x1F,0x10,0x31,0x31,0x34,
	0x33,0x38,0x30,0x30,0x37,0x38,0x30,0x30,
	0x30,0x30,0x30,0x30,0x30,
	0xff,0x11,0x81,0x03,'p','e','r'
};

int main()
{
	uint8_t test[] = {'2','2','2'};
	TLVEntity tlv;
	tlv.tag = 0xffff;
	tlv.length = 3;
	TLVPackage::CopyBuff2TlvValue(test,&tlv);

	uint8_t data[10] = {0};
	uint32_t len = 0;
	TLVPackage::Parse(&tlv, 1, data, len);

	PrintBufferHex(data,len);

	tlv.tag = 0;
	tlv.length = 0;
	free(tlv.value);
	tlv.value = NULL;

	uint32_t tlv_size = 0;
	TLVPackage::Construct(data, len, &tlv, tlv_size);
	Tlv_Debug(&tlv,tlv_size);

	Tlv_t tlvs[MAX_TLVOBJ_ARR];
	tlv_size = 0;
	TLVPackage::Construct(tlv1Data, sizeof(tlv1Data), tlvs, tlv_size);
	printf("tlv_size:%u\n",tlv_size);
	Tlv_Debug(tlvs,tlv_size);

	uint8_t tmp[100];
	uint32_t tmp_size = 0;
	TLVPackage::Parse(tlvs, tlv_size, tmp, tmp_size);
	printf("tmp_size:%d\n",tmp_size);
	PrintBufferHex(tmp,tmp_size);

	if(!memcmp(tlv1Data,tmp,sizeof(tlv1Data))) {
		printf("the data is same..\n");
	}
}
