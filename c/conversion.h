/*
* only used on little endian
*/

#ifndef CONVERSION_H
#define CONVERSION_H

#include <stdint.h>
#include <string.h>

uint32_t inline bswap_32(uint32_t x)  
{  
    return (((uint32_t)(x) & 0xff000000) >> 24) | \
           (((uint32_t)(x) & 0x00ff0000) >> 8) | \
           (((uint32_t)(x) & 0x0000ff00) << 8) | \
           (((uint32_t)(x) & 0x000000ff) << 24) ;  
}

uint64_t inline bswap_64(uint64_t x)  
{  
    return (((uint64_t)(x) & 0xff00000000000000ull) >> 56) | \
		   (((uint64_t)(x) & 0x00ff000000000000ull) >> 40) | \
		   (((uint64_t)(x) & 0x0000ff0000000000ull) >> 24) | \
		   (((uint64_t)(x) & 0x000000ff00000000ull) >> 8) | \
		   (((uint64_t)(x) & 0x00000000ff000000ull) << 8) | \
		   (((uint64_t)(x) & 0x0000000000ff0000ull) << 24) | \
		   (((uint64_t)(x) & 0x000000000000ff00ull) << 40) | \
		   (((uint64_t)(x) & 0x00000000000000ffull) << 56) ;
}

uint32_t inline le32toh_(uint32_t x) {
    return x;
}

uint32_t inline htole32_(uint32_t x) {
    return x;
}

uint32_t inline be32toh_(uint32_t x) {
    return bswap_32(x);
}

uint32_t inline htobe32_(uint32_t x) {
    return bswap_32(x);
}

uint64_t inline le64toh_(uint64_t x) {
    return x;
}

uint64_t inline htole64_(uint64_t x) {
    return x;
}

uint32_t inline be64toh_(uint64_t x) {
    return bswap_64(x);
}

uint64_t inline htobe64_(uint64_t x) {
    return bswap_64(x);
}

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return le32toh_(x);
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32_(x);
    memcpy(ptr, (char*)&v, 4);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    memcpy((char*)&x, ptr, 4);
    return be32toh_(x);
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32_(x);
    memcpy(ptr, (char*)&v, 4);
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64_(x);
    memcpy(ptr, (char*)&v, 8);
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return le64toh_(x);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64_(x);
    memcpy(ptr, (char*)&v, 8);
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    uint64_t x;
    memcpy((char*)&x, ptr, 8);
    return be64toh_(x);
}

#endif
