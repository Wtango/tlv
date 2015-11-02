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

uint8_t data[] =
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
	0xff,0x11,0x03,'p','e','r'
};

uint8_t tlv1Data[] = 
{
	0x22,0x19,0x21,0x6,0xf,0x4,0x4,0x0,0x0,
	0x0,0x22,0x4,0xd,0x2,0x0,0x0,0x23,0x9,
	0xd,0x7,0x53,0x75,0x63,0x63,0x65,0x73,0x73
};

int main()
{
#if 1
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

	if(!memcmp(tlv1Data,tmp,sizeof(tlv1Data))) {
		printf("the data is same..\n");
	}
#else

	Tlv_t tlv;
	tlv.tag = 0xa1;

	Tlv_t child1;
	child1.tag = 0x01;
	uint8_t child1_msg[] = {'c','h','i','l','d','1'};
	child1.length = sizeof(child1_msg);
	TLVPackage::CopyBuff2TlvValue(child1_msg, &child1);

	Tlv_t child2;
	child2.tag = 0x02;
	uint8_t child2_msg[] = {'c','h','i','l','d','2'};
	child2.length = sizeof(child2_msg);
	TLVPackage::CopyBuff2TlvValue(child2_msg, &child2);

	if(TLVPackage::AddTlv(&tlv,&child1))
		fprintf(stderr,"Add child1 error\n");
	if(TLVPackage::AddTlv(&tlv,&child2))
		fprintf(stderr,"Add child2 error\n");

	TLVPackage::Tlv_Debug(&tlv, 1);

	Tlv_t tlvs[MAX_TLVOBJ_SIZE];
	uint32_t tlvs_size = 0;
	TLVPackage::Construct(tlv.value, tlv.length, tlvs, tlvs_size);

	TLVPackage::Tlv_Debug(tlvs, tlvs_size);
#endif


}
