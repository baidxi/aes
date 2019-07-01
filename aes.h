#ifndef AES_AES_H
#define AES_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>

#define BLOCKSIZE 16

#define LOAD32H(x, y) \
  do { (x) = ((uint32_t)((y)[0] & 0xff)<<24) | ((uint32_t)((y)[1] & 0xff)<<16) | \
             ((uint32_t)((y)[2] & 0xff)<<8)  | ((uint32_t)((y)[3] & 0xff));} while(0)

#define STORE32H(x, y) \
  do { (y)[0] = (uint8_t)(((x)>>24) & 0xff); (y)[1] = (uint8_t)(((x)>>16) & 0xff);   \
       (y)[2] = (uint8_t)(((x)>>8) & 0xff); (y)[3] = (uint8_t)((x) & 0xff); } while(0)

/* extract a byte */
#define BYTE(x, n) (((x) >> (8 * (n))) & 0xff)

/* used for keyExpansion */
#define MIX(x) (((S[BYTE(x, 2)] << 24) & 0xff000000) ^ ((S[BYTE(x, 1)] << 16) & 0xff0000) ^ \
                ((S[BYTE(x, 0)] << 8) & 0xff00) ^ (S[BYTE(x, 3)] & 0xff))

#define ROF32(x, n)  (((x) << (n)) | ((x) >> (32-(n))))

#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32-(n))))

typedef struct{
    uint32_t eK[44], dK[44];    // encKey, decKey
    int Nr; // 10 rounds
}AesKey;

int loadStateArray(uint8_t state[4][4], const uint8_t *in);

int storeStateArray(uint8_t state[4][4], uint8_t *out);

int keyExpansion(const uint8_t *key, uint32_t keyLen, AesKey *aesKey);

int addRoundKey(uint8_t state[4][4], const uint32_t key[4]);

int subBytes(uint8_t state[4][4]);

int invSubBytes(uint8_t state[4][4]);

int shiftRows(uint8_t state[4][4]);

int invShiftRows(uint8_t state[4][4]);

uint8_t GMul(uint8_t a, uint8_t b);

int mixColumns(uint8_t state[4][4]);

int invMixColumns(uint8_t state[4][4]);

// data length must be multiple of 16B, so data need to be padded before encryption/decryption
int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len);

int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
int aesEncryptFile(FILE *in, FILE *out, char *key);
int aesDecryptFile(FILE *in, FILE *out, char *key);

#ifdef __cplusplus
}
#endif

#endif //AES_AES_H
