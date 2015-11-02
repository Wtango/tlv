#ifndef __TLVPACKAGE_H__
#define __TLVPACKAGE_H__

#include <typeinfo>
#include "TLVEntity.h"

#define MAX_TLVOBJ_SIZE 100

#define TLV_STRING_TAG 0x0d

class TLVPackage
{
public:
        TLVPackage();
        virtual ~TLVPackage();

	/* Construct the data into TLVEntity,the data would contain one or more TLVEntity Object */
        static int Construct(const uint8_t *data, uint32_t dataSize, TLVEntity *tlvEntity, uint32_t &entitySize);

	static int Construct(const uint8_t *data, uint32_t dataSize, Tlv_t *tlv);

	/* Paser TLVEntitys into data stream */
        static int Parse(const TLVEntity *tlvEntity,uint32_t entitySize, uint8_t *buffer, uint32_t &bufferLength);

	static int Parse(const TLVEntity *tlvEntity,uint8_t *buffer,uint32_t &bufferLength);

	static int CopyBuff2TlvValue(const void *buffer,Tlv_t *tlv);

	static uint8_t* CopyTlvValue2Buff(const Tlv_t *tlv,uint8_t *buffer);

	static int AddTlv(Tlv_t *tlv,Tlv_t *child_tlv);

	static int TlvAddData(Tlv_t *tlv, uint16_t tag, uint8_t *value, uint32_t value_len);

	static void Tlv_Debug(Tlv_t *tlvs,int tlv_size);

	template<class T> static void BasicValSet(Tlv_t *tlv, T par)
	{
	        tlv->length = sizeof(T);
	        *(T*)tlv->value = par;
	        if(typeid(T) == typeid(bool))
	                tlv->tag = 1;
	        else if(typeid(T) == typeid(int8_t))
	                tlv->tag = 2;
	        else if(typeid(T) ==  typeid(uint8_t))
	                tlv->tag = 3;
	        else if(typeid(T) == typeid(int16_t))
	                tlv->tag = 4;
	        else if(typeid(T) == typeid(uint16_t))
	                tlv->tag = 5;
	        else if(typeid(T) ==  typeid(int32_t))
	                tlv->tag = 6;
	        else if(typeid(T) == typeid(uint32_t))
	                tlv->tag = 7;
	        else if(typeid(T) == typeid(int64_t))
	                tlv->tag = 8;
	        else if(typeid(T) == typeid(uint64_t))
	                tlv->tag = 9;
	        else if(typeid(T) == typeid(float))
	                tlv->tag = 10;
	        else if(typeid(T) == typeid(double))
	                tlv->tag = 11;
	        else if(typeid(T) == typeid(char))
	                tlv->tag = 12;
		else if(typeid(T) == typeid(NULL))
        	        tlv->tag = 15;
	}

	template<class T> static T BasicValGet(Tlv_t *tlv)
	{
	        return *(T*)tlv->value;
	}


	static int StringValSet(Tlv_t *tlv, void *buffer, uint32_t len);

private:
	// helper function to scan the tag ID + length field and then
	// return a pointer to the beginning of value data
	// only parse the first TLVEntity in buffer
	static const uint8_t* GetTlvHeader(const uint8_t* buffer, uint32_t bufferLength, Tlv_t *tlv);

	static uint32_t GetLength(const uint8_t *data);

	static uint8_t* SetLength(uint32_t length, uint8_t *buffer);
};

#endif  //__TLVPACKAGE_H__
