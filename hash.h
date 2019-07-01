#ifndef HASH_H
#define HASH_H
#include <stdint.h>
#include <endian.h>

#define ARRAY_SIZE(_n) (sizeof(_n) / sizeof((_n)[0]))

#define MD5_DIGEST_LENGTH	16

typedef struct MD5_CTX {
	uint32_t lo, hi;
	uint32_t a, b, c, d;
	unsigned char buffer[64];
} MD5_CTX;

/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SET(n) \
	(*(uint32_t *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(block[(n)] = \
	(uint32_t)ptr[(n) * 4] | \
	((uint32_t)ptr[(n) * 4 + 1] << 8) | \
	((uint32_t)ptr[(n) * 4 + 2] << 16) | \
	((uint32_t)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(block[(n)])
#endif

#if BYTE_ORDER == BIG_ENDIAN

/* Copy a vector of big-endian uint32_t into a vector of bytes */
#define be32enc_vect(dst, src, len)	\
	memcpy((void *)dst, (const void *)src, (size_t)len)

/* Copy a vector of bytes into a vector of big-endian uint32_t */
#define be32dec_vect(dst, src, len)	\
	memcpy((void *)dst, (const void *)src, (size_t)len)

#else /* BYTE_ORDER != BIG_ENDIAN */

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
void be32enc_vect(unsigned char *dst, const uint32_t *src, size_t len);

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
void be32dec_vect(uint32_t *dst, const unsigned char *src, size_t len);

#endif /* BYTE_ORDER != BIG_ENDIAN */

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define ROTR(x, n)	((x >> n) | (x << (32 - n)))

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)

typedef struct SHA256Context {
	uint32_t state[8];
	uint64_t count;
	uint8_t buf[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

const char *md5_hash(FILE *f);
const char *sha256_hash(FILE *f);

#endif
