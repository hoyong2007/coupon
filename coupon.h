#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define IV_SIZE  12
#define KEY_SIZE 0x20
#define TAG_SIZE 0x10
#define AAD_SIZE 0x10

struct aes_gcm_ctx {
	unsigned char present[0x100];
	unsigned char coupon[0x100];
	unsigned char key[KEY_SIZE+1];
	unsigned char iv[IV_SIZE+1];
	unsigned char aad[AAD_SIZE+1];
	unsigned char tag[TAG_SIZE+1];
	int couponLen;
	int presentLen;
};

void dump(struct aes_gcm_ctx *coupon);
void aes_gcm_encrypt(struct aes_gcm_ctx *coupon);
unsigned int aes_gcm_decrypt(struct aes_gcm_ctx *coupon);