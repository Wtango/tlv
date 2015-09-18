#ifndef __TLVENTITY_H__
#define __TLVENTITY_H__

#include <stdint.h>

/*
 *Reference
 *http://www.cnblogs.com/liping13599168/archive/2011/06/15/2081366.html
 *http://my.oschina.net/maxid/blog/206546
 */

struct TLVEntity {
	uint8_t *Tag;			//Tag
	uint8_t *Length;		//Data Length
	uint8_t *Value;			//Data
	uint32_t TagSize;
	uint32_t LengthSize;
	TLVEntity *Sub_TLVEntity;
};

class TLVPackage
{
public:
	TLVPackage();
	virtual ~TLVPackage();

	static void Construct(uint8_t *data, uint32_t dataSize, TLVEntity *tlvEntity, uint32_t &entityLength);

	static void Parse();
};

#endif //__TLVENTITY_H__
