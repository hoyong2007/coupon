#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <dirent.h> 
#include "coupon.h"


void print_hex(unsigned char *pref, unsigned char *buf, unsigned int size)
{
    if (*pref)
        printf("%s : ", pref);

    for (int i=0 ; i<size ; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

void gen_rand_bytes(unsigned char *buf, unsigned int size)
{
	for (int i=0 ; i<size ; i++)
		buf[i] = rand() % 0x100;
	return;
}

void hex_to_bytes(unsigned char *dst, unsigned char *src, unsigned int size)
{
	int i;
	for (i=0 ; i<size ; i++) {
		char val[3] = {src[2*i], src[2*i + 1], '\x00'};
		sscanf(val, "%2hhx", &dst[i]);
	}
	dst[i] = '\0';
}

void bytes_to_hex(unsigned char *dst, unsigned char *src, unsigned int size)
{
	const char *hex = "0123456789ABCDEF";
	for (int i=0 ; i<size ; i++) {
		*dst++ = hex[(*src>>4)&0xF];
        *dst++ = hex[(*src++)&0xF];
	}
}

void init_coupon(struct aes_gcm_ctx *coupon)
{
	memset(coupon->present, 0, 0x100);
	memset(coupon->coupon, 0, 0x100);
	memset(coupon->tag, 0, TAG_SIZE+1);
	coupon->presentLen = 0;
	coupon->couponLen = 0;
}

int read_wrapper(int fd, unsigned char *buf, unsigned int size)
{
	int outlen;
	outlen = read(fd, buf, size);
	if (outlen > 0 && buf[outlen-1] == '\n')
		buf[(outlen--) - 1] = '\x00';
	return outlen;	
}

int check_str(unsigned char *str)
{
	int result = 1;
	for (; *str != '\0' ; str++) {
		result &= (*str >= 'a' && *str <= 'z');
	}
	return result;
}

void get_key(unsigned char *key)
{
	FILE *fp;
	unsigned char buf[KEY_SIZE*2 + 1];
	if (access("key.txt", F_OK) != -1) {
		fp = fopen("key.txt", "r");
		fread(buf, 1, KEY_SIZE*2, fp);
		hex_to_bytes(key, buf, KEY_SIZE);
	}
	else {
		fp = fopen("key.txt", "w");
		gen_rand_bytes(key, KEY_SIZE);
		bytes_to_hex(buf, key, KEY_SIZE);
		fwrite(buf, 1, KEY_SIZE*2, fp);
	}
}

void init(struct aes_gcm_ctx *coupon)
{
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);

	srand(time(NULL));
	gen_rand_bytes(coupon->iv, IV_SIZE);
	get_key(coupon->key);
	strncpy(coupon->aad, "coupon center v1", AAD_SIZE);
}

void welcome()
{
	printf("Welcome to Santa's Coupon Center!!\n\n");
	printf("How can I help you?\n");
	sleep(1);
}

void print_menu()
{
	printf("\n");
	printf("1. Show gift list\n");
	printf("2. Choose gift and get coupon\n");
	printf("3. Submit coupon and receive Santa's present\n");
	printf("4. exit\n");
}

// 1. Show gift list =====================
void show_gitfs()
{
	printf("Here's a gift list that we have :)\n");
	printf("============ gift list ===========\n");

	struct dirent *dir;
	DIR *d = opendir("./GiftBag");
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (dir->d_name[0] != '.')
	  			printf("%s\n", dir->d_name);
		}
		closedir(d);
	}
}

// 2. Choose gift and get coupon =====================
void get_wishes(struct aes_gcm_ctx *coupon)
{
	int len = 0;
	unsigned char tmp[0x100] = {'\0', };
	unsigned char name[0x40] = {'\0', };
	unsigned char gift[0x40] = {'\0', };

	printf("What's your name?\n");
	printf(" : ");
	read_wrapper(0, name, 0x30);

	printf("What do you want for the gift?\n");
	printf(" : ");
	len = read_wrapper(0, gift, 0x30);
	sprintf(tmp, "Santa's coupon for %s :)\nPresent: %s", name, gift);

	if(strstr(name, "flag") != NULL || strstr(gift, "flag") != NULL) {
    	printf("That's not for you~~\n");
    	exit(-1);
    }

    if (!check_str(name) || !check_str(gift)) {
    	printf("Bad kid nono...\n");
    	exit(-1);
    }

    len = strlen(tmp);
	strncpy(coupon->present, tmp, len);
	
	if (len % 16 != 0) {
		len = 16 * ((len+16) / 16);
	}
	coupon->presentLen = len;
}


void gen_coupon(struct aes_gcm_ctx *coupon)
{
	printf("\nOkay then, let's make some coupon for you\n");
	aes_gcm_encrypt(coupon);
	print_hex("Coupon", coupon->coupon, coupon->couponLen);
	print_hex("Tag", coupon->tag, TAG_SIZE);
}




// 3. Submit coupon and receive Santa's present ===================
void get_coupon(struct aes_gcm_ctx *coupon)
{
	unsigned char tmp_coupon[0x200] = {0, };
	unsigned char tmp_tag[0x20] = {0, };
	unsigned int tmp_len;

	printf("Hello, would you hand me the coupon you received?\n");
	printf("Coupon number : ");
	tmp_len = read_wrapper(0, tmp_coupon, 0x200);
	
	if (tmp_len%2 != 0) {
		printf("Coupon must be an even-length string!!\n");
		exit(-1);
	}
	coupon->couponLen = tmp_len/2;
	hex_to_bytes(coupon->coupon, tmp_coupon, coupon->couponLen);

	printf("Coupon's tag : ");
	tmp_len = read_wrapper(0, tmp_tag, 0x20);
	if (tmp_len != 0x20) {
		printf("Tag must be 16 bytes hex string!!\n");
		exit(-1);
	}
	hex_to_bytes(coupon->tag, tmp_tag, TAG_SIZE);
}

void read_coupon(struct aes_gcm_ctx *coupon)
{
	if (aes_gcm_decrypt(coupon) <= 0) {
		printf("Maybe this coupon is expired...\n");
		exit(-1);
	}
	printf("\n===== coupon contents =====\n");
	printf("%s", coupon->present);
	printf("\n===========================\n");
}


void send_present(struct aes_gcm_ctx *coupon)
{
	FILE *fp;
	unsigned char *gift_name = NULL;
	unsigned char gift_content[2048] = {'\0', };
	unsigned char filename[0x100] = {'\0', };

	gift_name = strstr(coupon->present, "Present: ") + 9;

	strcpy(filename, "./GiftBag/");
	strcat(filename, gift_name);
	
	if (access(filename, F_OK) != -1) {
		fp = fopen(filename, "r");
		fread(gift_content, 1, 2048, fp);
		printf("%s\n", gift_content);
	}
	else {
		printf("There's no such thing like \'%s\' :(\n", gift_name);
	}
}


int main()
{
	struct aes_gcm_ctx coupon = {0,};
	unsigned int gift_cnt = 0;

	init(&coupon);
	welcome();

	while (1) {
		int select = 0;
		print_menu();
		scanf("%d", &select);
		getchar();

		if (select == 1) {
			show_gitfs();
		}
		else if (select == 2) {
			if (gift_cnt >= 2) {
				printf("You such a greedy!!!\n");
				exit(-1);
			}
			else {
				init_coupon(&coupon);
				get_wishes(&coupon);
				gen_coupon(&coupon);
				gift_cnt++;
			}
		}
		else if (select == 3) {
			init_coupon(&coupon);
			get_coupon(&coupon);
			read_coupon(&coupon);
			send_present(&coupon);
		}
		else if (select == 4) {
			printf("Thank you for using our service :)\n");
			printf("Have a Merry Christmas!\n");
			break;
		}
		else
			printf("Pardon me?\n");
	}

	return 0;
}