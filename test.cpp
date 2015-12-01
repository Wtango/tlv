#include <stdio.h>
#include <string.h>

#include "TLVPackage.h"

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

uint8_t tlv1Data[] = 
{
	0x22,0x19,0x21,0x6,0xf,0x4,0x4,0x0,0x0,
	0x0,0x22,0x4,0xd,0x2,0x0,0x0,0x23,0x9,
	0xd,0x7,0x53,0x75,0x63,0x63,0x65,0x73,0x73
};

int main()
{
	uint32_t tlv_size = 0;
	Tlv_t tlvs[MAX_TLVOBJ_SIZE];
	Tlv_t tlvs2[MAX_TLVOBJ_SIZE];
	if(TLVPackage::Construct(tlv1Data, sizeof(tlv1Data), tlvs, tlv_size)) {
		fprintf(stderr,"Construct error\n");
	}
	printf("tlv_size:%u\n",tlv_size);
	TLVPackage::Tlv_Debug(tlvs,tlv_size);

	tlv_size = 0;
	if(TLVPackage::Construct(tlvs[0].value,tlvs[0].length ,tlvs2,tlv_size)) {
		fprintf(stderr,"Construct error\n");
	}
	TLVPackage::Tlv_Debug(tlvs2, tlv_size);

	uint8_t tmp[100];
	uint32_t tmp_size = 0;
	TLVPackage::Parse(tlvs2, tlv_size, tmp, tmp_size);
	printf("tmp_size:%d\n",tmp_size);
	PrintBufferHex(tmp,tmp_size);

	if(!memcmp(tlv1Data + 2,tmp,sizeof(tlv1Data) - 2)) {
		printf("the data is same..\n");
	}
	else {
		printf("the data is not same..\n");
	}
}
