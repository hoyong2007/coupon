CC=gcc
CFLAGS=-lcrypto -s
TARGET=coupon

$(TARGET): coupon.o encrypter.o
	$(CC) -o $(TARGET) coupon.o encrypter.o $(CFLAGS)
	rm coupon.o encrypter.o

encrypter.o: encrypter.c coupon.h
	$(CC) -c -o encrypter.o encrypter.c $(CFLAGS)

coupon.o: coupon.c coupon.h
	$(CC) -c -o coupon.o coupon.c $(CFLAGS)

clean:
	rm -f *.o
	rm -f coupon
