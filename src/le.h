#ifndef WEED_LE_H
#define WEED_LE_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline void weed_store_u32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static inline void weed_store_u64_le(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
	p[4] = (uint8_t)(v >> 32);
	p[5] = (uint8_t)(v >> 40);
	p[6] = (uint8_t)(v >> 48);
	p[7] = (uint8_t)(v >> 56);
}

static inline int weed_write_u32_le(FILE *f, uint32_t v)
{
	uint8_t b[4];
	weed_store_u32_le(b, v);
	return fwrite(b, 1, 4, f) == 4 ? 0 : -1;
}

static inline int weed_write_u64_le(FILE *f, uint64_t v)
{
	uint8_t b[8];
	weed_store_u64_le(b, v);
	return fwrite(b, 1, 8, f) == 8 ? 0 : -1;
}

#endif /* WEED_LE_H */
