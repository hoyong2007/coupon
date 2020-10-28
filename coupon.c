#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IV_SIZE  12
#define KEY_SIZE 32
#define TAG_SIZE 16

static const unsigned char gcm_iv[] = {	// 12 bytes 0
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
/*
gcm_key (32)
gcm_iv (12)
gcm_pt ()
gcm_ct ()
gcm_aad (16)
gcm_tag (16)
*/

void welcome()
{
	printf("Welcome to Santa's Coupon Center!!\n\n");
	printf("Please give me coupon\n");
}


void get_coupon(unsigned char *coupon, unsigned char *tag)
{
	printf("Coupon number : ");
	read(0, coupon, 0x300);
	printf("Coupon's tag : ");
	read(0, tag, 0x10);
}


void read_coupon()
{

}


void send_present()
{}


int main()
{
	unsigned char coupon[0x300] = {0, };
	unsigned char tag[0x10] = {0, };

	welcome();

	get_coupon(coupon, tag);

	read_coupon();

	send_present();

	return 0;
}