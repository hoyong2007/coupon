#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "coupon.h"
/*
void dump(struct aes_gcm_ctx *coupon)
{
    printf("CouponLen: %d\n", coupon->couponLen);
    printf("Coupon: ");
    BIO_dump_fp(stdout, coupon->coupon, 0x300);
    
    printf("PresentLen: %d\n", coupon->presentLen);
    printf("Present: ");
    BIO_dump_fp(stdout, coupon->present, 0x300);
    
    printf("Key: ");
    BIO_dump_fp(stdout, coupon->key, KEY_SIZE);
    
    printf("IV: ");
    BIO_dump_fp(stdout, coupon->iv, IV_SIZE);
    
    printf("aad: ");
    BIO_dump_fp(stdout, coupon->aad, AAD_SIZE);

    printf("Tag: ");
    BIO_dump_fp(stdout, coupon->tag, TAG_SIZE);
}
*/

void aes_gcm_encrypt(struct aes_gcm_ctx *coupon)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[0x301];
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, coupon->key, coupon->iv);
    EVP_EncryptUpdate(ctx, NULL, &coupon->couponLen, coupon->aad, AAD_SIZE);
    EVP_EncryptUpdate(ctx, coupon->coupon, &coupon->couponLen, coupon->present, coupon->presentLen);
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, coupon->tag);
    EVP_CIPHER_CTX_free(ctx);

    //dump(coupon);
}

unsigned int aes_gcm_decrypt(struct aes_gcm_ctx *coupon)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, rv;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, IV_SIZE, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, coupon->key, coupon->iv);
    EVP_DecryptUpdate(ctx, NULL, &coupon->presentLen, coupon->aad, AAD_SIZE);
    EVP_DecryptUpdate(ctx, coupon->present, &coupon->presentLen, coupon->coupon, coupon->couponLen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void *)coupon->tag);
    rv = EVP_DecryptFinal_ex(ctx, coupon->present, &coupon->presentLen);
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}
